"""Asyncio TCP server for secure file transfer."""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import shutil
import tempfile
import uuid
from pathlib import Path
from typing import Callable

from loguru import logger

from securetransfer.core.compression import Compressor
from securetransfer.core.encryption import AESCipher, KeyManager
from securetransfer.core.protocol import (
    FrameReader,
    Packet,
    PacketBuilder,
    PacketType,
)
from securetransfer.db.models import TransferRepository

CONNECTION_TIMEOUT = 30.0
PACKET_TIMEOUT = 10.0


def _manifest_transfer_id_to_wire(transfer_id_str: str) -> int:
    """Convert manifest transfer_id (UUID string) to 64-bit wire format."""
    return int.from_bytes(uuid.UUID(transfer_id_str).bytes[:8], "big")


class TransferServer:
    """Asyncio TCP server that receives files; handshake, manifest, pieces, verify."""

    def __init__(
        self,
        host: str,
        port: int,
        db_repo: TransferRepository,
        output_dir: str | Path | None = None,
        progress_callback: Callable[[str, str, int, int], None] | None = None,
        on_complete_callback: Callable[[str, str, str | None, bool], None] | None = None,
    ) -> None:
        """Initialize server with bind address and DB repository.

        Args:
            host: Bind host (e.g. '0.0.0.0').
            port: Bind port.
            db_repo: Repository for creating/updating Transfer and PieceStatus.
            output_dir: If set, save received files here (filename from manifest).
            progress_callback: Called with (transfer_id, filename, completed_pieces, total_pieces).
            on_complete_callback: Called with (transfer_id, filename, save_path or None, verified).
        """
        self._host = host
        self._port = port
        self._db_repo = db_repo
        self._output_dir = Path(output_dir) if output_dir else None
        self._progress_cb = progress_callback
        self._on_complete_cb = on_complete_callback
        self._server: asyncio.Server | None = None

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

    async def _send_packet(
        self,
        writer: asyncio.StreamWriter,
        packet: Packet,
        write_lock: asyncio.Lock,
    ) -> None:
        """Send one packet; must hold write_lock to avoid concurrent write corruption."""
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
        """Full server-side session: handshake, manifest, receive pieces, verify, complete."""
        peer = writer.get_extra_info("peername", ("unknown",))[:2]
        remote_host = f"{peer[0]}:{peer[1]}"
        write_lock = asyncio.Lock()
        wire_transfer_id: int = 0
        transfer_id_str: str = ""
        manifest: dict | None = None
        aes_cipher: AESCipher | None = None
        compressor = Compressor()
        key_manager = KeyManager()

        def _send_error(msg: str) -> None:
            try:
                p = PacketBuilder.build_error(msg, wire_transfer_id)
                asyncio.create_task(
                    self._send_packet(writer, p, write_lock)
                )
            except Exception:
                pass

        try:
            # 1. Read HANDSHAKE_INIT
            init_pkt = await asyncio.wait_for(
                FrameReader.read_packet(reader),
                timeout=PACKET_TIMEOUT,
            )
            if init_pkt.packet_type != PacketType.HANDSHAKE_INIT:
                _send_error("expected HANDSHAKE_INIT")
                return
            handshake = json.loads(init_pkt.payload.decode("utf-8"))
            client_public_b64 = handshake["public_key"]
            salt_b64 = handshake["salt"]
            client_public = base64.b64decode(client_public_b64)
            salt = base64.b64decode(salt_b64)
            logger.info("handshake init from {} public_key_len={} salt_len={}", remote_host, len(client_public), len(salt))

            # 2. Server keypair, derive shared secret, derive AES key
            server_private, server_public = key_manager.generate_keypair()
            shared = key_manager.derive_shared_secret(server_private, client_public)
            aes_key = key_manager.derive_symmetric_key(shared, salt)
            aes_cipher = AESCipher(aes_key)
            session_id = uuid.uuid4().int & 0x7FFF_FFFF_FFFF_FFFF

            # 3. Send HANDSHAKE_RESP
            resp_pkt = PacketBuilder.build_handshake_resp(server_public, session_id)
            await self._send_packet(writer, resp_pkt, write_lock)
            logger.info("handshake resp sent session_id={}", session_id)

            # 4. Read MANIFEST
            man_pkt = await asyncio.wait_for(
                FrameReader.read_packet(reader),
                timeout=PACKET_TIMEOUT,
            )
            if man_pkt.packet_type != PacketType.MANIFEST:
                _send_error("expected MANIFEST")
                return
            manifest = json.loads(man_pkt.payload.decode("utf-8"))
            transfer_id_str = manifest["transfer_id"]
            wire_transfer_id = _manifest_transfer_id_to_wire(transfer_id_str)
            existing = await self._db_repo.get_transfer(transfer_id_str)
            if not existing:
                await self._db_repo.create_transfer(
                    transfer_id=transfer_id_str,
                    direction="receive",
                    filename=manifest["filename"],
                    file_size=manifest["total_size"],
                    total_pieces=manifest["total_pieces"],
                    remote_host=remote_host,
                    file_hash=manifest["file_hash"],
                )
            else:
                await self._db_repo.update_transfer_status(transfer_id_str, "in_progress")
            logger.info("manifest received transfer_id={} filename={} pieces={}", transfer_id_str, manifest["filename"], manifest["total_pieces"])

            piece_hashes = manifest.get("piece_hashes", {})
            total_pieces = manifest["total_pieces"]
            pieces_data: dict[int, bytes] = {}

            # 5. Loop: read PIECE → decompress → decrypt → verify hash → DB → ACK/NACK
            while len(pieces_data) < total_pieces:
                pkt = await asyncio.wait_for(
                    FrameReader.read_packet(reader),
                    timeout=CONNECTION_TIMEOUT,
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
                    await self._db_repo.update_piece_status(transfer_id_str, piece_index, "failed")
                    await self._db_repo.increment_piece_attempts(transfer_id_str, piece_index)
                    nack = PacketBuilder.build_nack(piece_index, wire_transfer_id)
                    await self._send_packet(writer, nack, write_lock)
                    continue

                expected_hash = piece_hashes.get(str(piece_index))
                if not expected_hash:
                    _send_error(f"unknown piece index {piece_index}")
                    return
                piece_hash = hashlib.sha256(plain).hexdigest().lower()
                if piece_hash != expected_hash.strip().lower():
                    logger.warning("piece {} hash mismatch", piece_index)
                    await self._db_repo.update_piece_status(transfer_id_str, piece_index, "failed")
                    await self._db_repo.increment_piece_attempts(transfer_id_str, piece_index)
                    nack = PacketBuilder.build_nack(piece_index, wire_transfer_id)
                    await self._send_packet(writer, nack, write_lock)
                    continue

                pieces_data[piece_index] = plain
                await self._db_repo.mark_piece_verified(transfer_id_str, piece_index)
                if self._progress_cb:
                    self._progress_cb(transfer_id_str, manifest["filename"], len(pieces_data), total_pieces)
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
                    await self._db_repo.update_transfer_status(transfer_id_str, "failed")
                    _send_error("file hash verification failed")
                    if self._on_complete_cb:
                        self._on_complete_cb(transfer_id_str, manifest["filename"], None, False)
                    return
                verified = True
                if self._output_dir:
                    self._output_dir.mkdir(parents=True, exist_ok=True)
                    out_file = self._output_dir / manifest["filename"]
                    shutil.copy2(tmp_path, out_file)
                    save_path = str(out_file.resolve())
            finally:
                Path(tmp_path).unlink(missing_ok=True)

            await self._db_repo.update_transfer_status(transfer_id_str, "completed")
            if self._on_complete_cb:
                self._on_complete_cb(transfer_id_str, manifest["filename"], save_path, verified)
            complete_pkt = Packet(PacketType.TRANSFER_COMPLETE, b"{}", transfer_id=wire_transfer_id)
            await self._send_packet(writer, complete_pkt, write_lock)
            logger.info("transfer complete transfer_id={}", transfer_id_str)

        except asyncio.TimeoutError as e:
            logger.warning("timeout from {}: {}", remote_host, e)
            _send_error("timeout")
        except Exception as e:
            logger.exception("handle_client error from {}: {}", remote_host, e)
            _send_error(str(e))
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass
