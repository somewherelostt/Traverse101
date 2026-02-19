"""Asyncio TCP server for secure file transfer.

Rate limiting: max concurrent per IP, token bucket per connection, ban after
failed handshakes. Security: ephemeral DH keys (forward secrecy), validated
packet fields, max transfer size, sanitized filenames, sensitive bytes zeroed.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import shutil
import tempfile
import time
import uuid
from pathlib import Path
from typing import Callable

from loguru import logger

from securetransfer import config
from securetransfer.core.compression import Compressor
from securetransfer.core.encryption import AESCipher, KeyManager
from securetransfer.core.protocol import (
    FrameReader,
    Packet,
    PacketBuilder,
    PacketType,
)
from securetransfer.core.security import sanitize_filename, secure_compare, zero_out_sensitive
from securetransfer.db.models import TransferRepository


def _manifest_transfer_id_to_wire(transfer_id_str: str) -> int:
    """Convert manifest transfer_id (UUID string) to 64-bit wire format."""
    return int.from_bytes(uuid.UUID(transfer_id_str).bytes[:8], "big")


class ThrottledReader:
    """Token bucket: max bytes per second per connection (asyncio, no external libs)."""

    __slots__ = ("_reader", "_rate", "_capacity", "_tokens", "_last_time", "_lock")

    def __init__(
        self,
        reader: asyncio.StreamReader,
        rate_bytes_per_sec: float,
        capacity_bytes: float | None = None,
    ) -> None:
        if capacity_bytes is None:
            capacity_bytes = rate_bytes_per_sec
        self._reader = reader
        self._rate = float(rate_bytes_per_sec)
        self._capacity = float(capacity_bytes)
        self._tokens = self._capacity
        self._last_time = time.monotonic()
        self._lock = asyncio.Lock()

    async def readexactly(self, n: int) -> bytes:
        """Read exactly n bytes, throttled by token bucket."""
        async with self._lock:
            now = time.monotonic()
            self._tokens = min(
                self._capacity,
                self._tokens + (now - self._last_time) * self._rate,
            )
            self._last_time = now
            while self._tokens < n:
                wait = (n - self._tokens) / self._rate
                await asyncio.sleep(wait)
                now = time.monotonic()
                self._tokens = min(
                    self._capacity,
                    self._tokens + (now - self._last_time) * self._rate,
                )
                self._last_time = now
            self._tokens -= n
        return await self._reader.readexactly(n)


class TransferServer:
    """Asyncio TCP server that receives files; handshake, manifest, pieces, verify.

    Rate limiting: max 5 concurrent per IP, 10 MB/s per connection (token bucket),
    ban IP after 3 failed handshakes within 60 seconds. Forward secrecy: server
    uses ephemeral keypair per connection (DH keys are ephemeral).
    """

    def __init__(
        self,
        host: str,
        port: int,
        db_repo: TransferRepository,
        output_dir: str | Path | None = None,
        progress_callback: Callable[[str, str, int, int], None] | None = None,
        on_complete_callback: Callable[[str, str, str | None, bool], None] | None = None,
    ) -> None:
        self._host = host
        self._port = port
        self._db_repo = db_repo
        self._output_dir = Path(output_dir) if output_dir else None
        self._progress_cb = progress_callback
        self._on_complete_cb = on_complete_callback
        self._server: asyncio.Server | None = None
        # Rate limiting: per-IP concurrent count
        self._concurrent_per_ip: dict[str, int] = {}
        self._concurrent_lock = asyncio.Lock()
        # Failed handshakes: (ip, timestamp) for ban check (3 in 60s)
        self._failed_handshakes: list[tuple[str, float]] = []
        self._failed_lock = asyncio.Lock()

    async def start(self) -> None:
        """Start the asyncio TCP server."""
        self._server = await asyncio.start_server(
            self._handle_client,
            self._host,
            self._port,
        )
        logger.info("Server listening on {}:{}", self._host, self._port)

    async def stop(self) -> None:
        """Stop the server and close all connections."""
        if self._server:
            self._server.close()
            await self._server.wait_closed()
            self._server = None
            logger.info("Server stopped")

    def _peer_ip(self, writer: asyncio.StreamWriter) -> str:
        peer = writer.get_extra_info("peername", ("unknown", 0))[:2]
        return str(peer[0])

    async def _is_banned(self, ip: str) -> bool:
        """True if IP has >= threshold failed handshakes in the last window_sec."""
        async with self._failed_lock:
            now = time.monotonic()
            cutoff = now - config.FAILED_HANDSHAKE_BAN_WINDOW_SEC
            self._failed_handshakes = [(i, t) for i, t in self._failed_handshakes if t > cutoff]
            count = sum(1 for i, _ in self._failed_handshakes if i == ip)
            return count >= config.FAILED_HANDSHAKE_BAN_THRESHOLD

    async def _record_failed_handshake(self, ip: str) -> None:
        async with self._failed_lock:
            self._failed_handshakes.append((ip, time.monotonic()))

    async def _concurrent_acquire(self, ip: str) -> bool:
        """Increment concurrent count for IP; return False if already at max."""
        async with self._concurrent_lock:
            n = self._concurrent_per_ip.get(ip, 0)
            if n >= config.MAX_CONCURRENT_CONNECTIONS_PER_IP:
                return False
            self._concurrent_per_ip[ip] = n + 1
            return True

    async def _concurrent_release(self, ip: str) -> None:
        async with self._concurrent_lock:
            n = self._concurrent_per_ip.get(ip, 0)
            if n <= 1:
                self._concurrent_per_ip.pop(ip, None)
            else:
                self._concurrent_per_ip[ip] = n - 1

    async def _send_packet(
        self,
        writer: asyncio.StreamWriter,
        packet: Packet,
        write_lock: asyncio.Lock,
    ) -> None:
        async with write_lock:
            data = packet.to_bytes()
            writer.write(data)
            await writer.drain()
        logger.debug(
            "sent packet type={} transfer_id={} payload_len={}",
            packet.packet_type.name,
            packet.transfer_id,
            packet.payload_length,
        )

    async def _handle_client(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        peer = writer.get_extra_info("peername", ("unknown",))[:2]
        remote_host = f"{peer[0]}:{peer[1]}"
        remote_ip = self._peer_ip(writer)
        write_lock = asyncio.Lock()
        wire_transfer_id: int = 0
        transfer_id_str: str = ""
        manifest: dict | None = None
        aes_cipher: AESCipher | None = None
        compressor = Compressor()
        key_manager = KeyManager()

        # Sensitive buffers to zero in finally (forward secrecy: ephemeral keys;
        # zero-out shared secret and AES key after use).
        server_private_arr: bytearray | None = None
        shared_arr: bytearray | None = None
        aes_key_arr: bytearray | None = None

        def _send_error(msg: str) -> None:
            try:
                p = PacketBuilder.build_error(msg, wire_transfer_id)
                asyncio.create_task(self._send_packet(writer, p, write_lock))
            except Exception:
                pass

        # --- Rate limit: ban check ---
        if await self._is_banned(remote_ip):
            try:
                await self._db_repo.add_audit_log(
                    "ip_banned",
                    f"Rejected connection from banned IP {remote_ip}",
                    severity="warning",
                    remote_ip=remote_ip,
                )
            except Exception:
                pass
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass
            return

        # --- Rate limit: max concurrent per IP ---
        if not await self._concurrent_acquire(remote_ip):
            try:
                await self._db_repo.add_audit_log(
                    "connection_rejected",
                    f"Too many concurrent connections from {remote_ip}",
                    severity="warning",
                    remote_ip=remote_ip,
                )
            except Exception:
                pass
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass
            return

        try:
            try:
                await self._db_repo.add_audit_log(
                    "connection",
                    f"Connection from {remote_host}",
                    severity="info",
                    remote_ip=remote_ip,
                )
            except Exception:
                pass

            # Token bucket: limit read rate per connection (10 MB/s)
            throttled = ThrottledReader(
                reader,
                config.RATE_LIMIT_BYTES_PER_SEC,
                capacity_bytes=config.RATE_LIMIT_BYTES_PER_SEC,
            )
            max_payload = config.MAX_PAYLOAD_SIZE

            # 1. Read HANDSHAKE_INIT (validate payload size via read_packet)
            init_pkt = await asyncio.wait_for(
                FrameReader.read_packet(throttled, max_payload_size=max_payload),
                timeout=config.PACKET_TIMEOUT,
            )
            if init_pkt.packet_type != PacketType.HANDSHAKE_INIT:
                _send_error("expected HANDSHAKE_INIT")
                await self._record_failed_handshake(remote_ip)
                try:
                    await self._db_repo.add_audit_log(
                        "handshake_failed",
                        f"Expected HANDSHAKE_INIT from {remote_host}",
                        severity="warning",
                        remote_ip=remote_ip,
                    )
                except Exception:
                    pass
                return
            try:
                handshake = json.loads(init_pkt.payload.decode("utf-8"))
                client_public_b64 = handshake["public_key"]
                salt_b64 = handshake["salt"]
                client_public = base64.b64decode(client_public_b64)
                salt = base64.b64decode(salt_b64)
            except Exception as e:
                logger.warning("handshake parse failed from {}: {}", remote_host, e)
                await self._record_failed_handshake(remote_ip)
                try:
                    await self._db_repo.add_audit_log(
                        "handshake_failed",
                        f"Handshake parse failed from {remote_host}: {e}",
                        severity="warning",
                        remote_ip=remote_ip,
                    )
                except Exception:
                    pass
                _send_error("invalid handshake")
                return
            logger.info(
                "handshake init from {} public_key_len={} salt_len={}",
                remote_host,
                len(client_public),
                len(salt),
            )

            # 2. Server ephemeral keypair (DH forward secrecy: keys are ephemeral per session)
            try:
                server_private, server_public = key_manager.generate_keypair()
                server_private_arr = bytearray(server_private)
                shared = key_manager.derive_shared_secret(server_private_arr, client_public)
                shared_arr = bytearray(shared)
                aes_key = key_manager.derive_symmetric_key(bytes(shared_arr), salt)
                aes_key_arr = bytearray(aes_key)
                aes_cipher = AESCipher(bytes(aes_key_arr))
                session_id = uuid.uuid4().int & 0x7FFF_FFFF_FFFF_FFFF
            except Exception as e:
                logger.warning("handshake key derivation failed from {}: {}", remote_host, e)
                await self._record_failed_handshake(remote_ip)
                try:
                    await self._db_repo.add_audit_log(
                        "handshake_failed",
                        f"Handshake key derivation failed from {remote_host}: {e}",
                        severity="warning",
                        remote_ip=remote_ip,
                    )
                except Exception:
                    pass
                _send_error("handshake failed")
                return

            try:
                await self._db_repo.add_audit_log(
                    "handshake",
                    f"Handshake OK session_id={session_id} from {remote_host}",
                    severity="info",
                    remote_ip=remote_ip,
                )
            except Exception:
                pass

            # 3. Send HANDSHAKE_RESP
            resp_pkt = PacketBuilder.build_handshake_resp(server_public, session_id)
            await self._send_packet(writer, resp_pkt, write_lock)
            logger.info("handshake resp sent session_id={}", session_id)

            # 4. Read MANIFEST
            man_pkt = await asyncio.wait_for(
                FrameReader.read_packet(throttled, max_payload_size=max_payload),
                timeout=config.PACKET_TIMEOUT,
            )
            if man_pkt.packet_type != PacketType.MANIFEST:
                _send_error("expected MANIFEST")
                return
            manifest = json.loads(man_pkt.payload.decode("utf-8"))
            transfer_id_str = manifest["transfer_id"]
            wire_transfer_id = _manifest_transfer_id_to_wire(transfer_id_str)

            # Validate all incoming fields: max transfer size (configurable)
            total_size = int(manifest["total_size"])
            if total_size < 0 or total_size > config.MAX_TRANSFER_SIZE:
                _send_error(
                    f"Transfer size {total_size} exceeds maximum {config.MAX_TRANSFER_SIZE}"
                )
                try:
                    await self._db_repo.add_audit_log(
                        "transfer_rejected",
                        f"Transfer size {total_size} exceeds limit from {remote_host}",
                        severity="warning",
                        transfer_id=transfer_id_str,
                        remote_ip=remote_ip,
                    )
                except Exception:
                    pass
                return

            # Path traversal prevention: sanitize filename from manifest
            raw_filename = manifest.get("filename", "unnamed")
            safe_filename = sanitize_filename(raw_filename)
            manifest["filename"] = safe_filename

            existing = await self._db_repo.get_transfer(transfer_id_str)
            if not existing:
                await self._db_repo.create_transfer(
                    transfer_id=transfer_id_str,
                    direction="receive",
                    filename=safe_filename,
                    file_size=total_size,
                    total_pieces=manifest["total_pieces"],
                    remote_host=remote_host,
                    file_hash=manifest["file_hash"],
                )
            else:
                await self._db_repo.update_transfer_status(transfer_id_str, "in_progress")
            logger.info(
                "manifest received transfer_id={} filename={} pieces={}",
                transfer_id_str,
                safe_filename,
                manifest["total_pieces"],
            )

            piece_hashes = manifest.get("piece_hashes", {})
            total_pieces = manifest["total_pieces"]
            pieces_data: dict[int, bytes] = {}

            # 5. Loop: read PIECE → decompress → decrypt → verify hash (timing-safe) → DB → ACK/NACK
            while len(pieces_data) < total_pieces:
                pkt = await asyncio.wait_for(
                    FrameReader.read_packet(throttled, max_payload_size=max_payload),
                    timeout=config.CONNECTION_TIMEOUT,
                )
                if pkt.packet_type == PacketType.TRANSFER_COMPLETE:
                    break
                if pkt.packet_type != PacketType.PIECE:
                    _send_error(f"expected PIECE or TRANSFER_COMPLETE, got {pkt.packet_type}")
                    return
                body = json.loads(pkt.payload.decode("utf-8"))
                piece_index = int(body["piece_index"])
                raw_enc = base64.b64decode(body["data"])
                logger.debug("received PIECE index={} enc_len={}", piece_index, len(raw_enc))

                try:
                    decrypted = aes_cipher.decrypt(raw_enc)
                    plain = compressor.decompress(decrypted)
                except Exception as e:
                    logger.warning("piece {} decrypt/decompress failed: {}", piece_index, e)
                    await self._db_repo.update_piece_status(
                        transfer_id_str, piece_index, "failed"
                    )
                    await self._db_repo.increment_piece_attempts(
                        transfer_id_str, piece_index
                    )
                    nack = PacketBuilder.build_nack(piece_index, wire_transfer_id)
                    await self._send_packet(writer, nack, write_lock)
                    continue

                expected_hash = piece_hashes.get(str(piece_index))
                if not expected_hash:
                    _send_error(f"unknown piece index {piece_index}")
                    return
                # Timing attack resistance: use hmac.compare_digest for hash comparison
                piece_hash = hashlib.sha256(plain).hexdigest().lower()
                if not secure_compare(piece_hash, expected_hash.strip().lower()):
                    logger.warning("piece {} hash mismatch", piece_index)
                    await self._db_repo.update_piece_status(
                        transfer_id_str, piece_index, "failed"
                    )
                    await self._db_repo.increment_piece_attempts(
                        transfer_id_str, piece_index
                    )
                    nack = PacketBuilder.build_nack(piece_index, wire_transfer_id)
                    await self._send_packet(writer, nack, write_lock)
                    continue

                pieces_data[piece_index] = plain
                await self._db_repo.mark_piece_verified(transfer_id_str, piece_index)
                if self._progress_cb:
                    self._progress_cb(
                        transfer_id_str,
                        safe_filename,
                        len(pieces_data),
                        total_pieces,
                    )
                ack = PacketBuilder.build_ack(piece_index, wire_transfer_id)
                await self._send_packet(writer, ack, write_lock)
                logger.debug("ACK piece {}", piece_index)

            # 6. Verify full file hash, send TRANSFER_COMPLETE
            if len(pieces_data) != total_pieces:
                await self._db_repo.update_transfer_status(transfer_id_str, "failed")
                _send_error("not all pieces received")
                return

            with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as f:
                for i in range(total_pieces):
                    f.write(pieces_data[i])
                tmp_path = f.name
            save_path: str | None = None
            verified = False
            try:
                from securetransfer.core.chunker import FileChunker

                chunker = FileChunker(tmp_path)
                if not chunker.verify_file(tmp_path, manifest["file_hash"]):
                    await self._db_repo.update_transfer_status(
                        transfer_id_str, "failed"
                    )
                    _send_error("file hash verification failed")
                    if self._on_complete_cb:
                        self._on_complete_cb(
                            transfer_id_str, safe_filename, None, False
                        )
                    return
                verified = True
                if self._output_dir:
                    self._output_dir.mkdir(parents=True, exist_ok=True)
                    out_file = self._output_dir / safe_filename
                    shutil.copy2(tmp_path, out_file)
                    save_path = str(out_file.resolve())
            finally:
                Path(tmp_path).unlink(missing_ok=True)

            await self._db_repo.update_transfer_status(transfer_id_str, "completed")
            try:
                await self._db_repo.add_audit_log(
                    "transfer_complete",
                    f"Transfer {transfer_id_str} {safe_filename} from {remote_host}",
                    severity="info",
                    transfer_id=transfer_id_str,
                    remote_ip=remote_ip,
                )
            except Exception:
                pass
            if self._on_complete_cb:
                self._on_complete_cb(
                    transfer_id_str, safe_filename, save_path, verified
                )
            complete_pkt = Packet(
                PacketType.TRANSFER_COMPLETE, b"{}", transfer_id=wire_transfer_id
            )
            await self._send_packet(writer, complete_pkt, write_lock)
            logger.info("transfer complete transfer_id={}", transfer_id_str)

        except asyncio.TimeoutError as e:
            logger.warning("timeout from {}: {}", remote_host, e)
            _send_error("timeout")
            try:
                await self._db_repo.add_audit_log(
                    "error",
                    f"Timeout from {remote_host}: {e}",
                    severity="warning",
                    transfer_id=transfer_id_str or None,
                    remote_ip=remote_ip,
                )
            except Exception:
                pass
        except Exception as e:
            logger.exception("handle_client error from {}: {}", remote_host, e)
            _send_error(str(e))
            try:
                await self._db_repo.add_audit_log(
                    "error",
                    f"Handle client error from {remote_host}: {e}",
                    severity="error",
                    transfer_id=transfer_id_str or None,
                    remote_ip=remote_ip,
                )
            except Exception:
                pass
        finally:
            await self._concurrent_release(remote_ip)
            # Zero-out sensitive bytes (shared secrets, AES keys) after use
            if server_private_arr is not None:
                zero_out_sensitive(server_private_arr)
            if shared_arr is not None:
                zero_out_sensitive(shared_arr)
            if aes_key_arr is not None:
                zero_out_sensitive(aes_key_arr)
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass
