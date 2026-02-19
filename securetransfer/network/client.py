"""Asyncio TCP client for secure file transfer."""

from __future__ import annotations

import asyncio
import base64
import json
import uuid
from typing import Any

from loguru import logger

from securetransfer.core.chunker import FileChunker, TransferManifest
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
MAX_PIECE_RETRIES = 3


def _manifest_transfer_id_to_wire(transfer_id_str: str) -> int:
    """Convert manifest transfer_id (UUID string) to 64-bit wire format."""
    return int.from_bytes(uuid.UUID(transfer_id_str).bytes[:8], "big")


class TransferClient:
    """Asyncio TCP client that sends files; handshake, manifest, pieces, complete."""

    def __init__(
        self,
        host: str,
        port: int,
        db_repo: TransferRepository,
    ) -> None:
        """Initialize client with server address and DB repository.

        Args:
            host: Server host.
            port: Server port.
            db_repo: Repository for creating/updating Transfer and PieceStatus.
        """
        self._host = host
        self._port = port
        self._db_repo = db_repo

    async def _send_packet(
        self,
        writer: asyncio.StreamWriter,
        packet: Packet,
        write_lock: asyncio.Lock,
    ) -> None:
        """Send one packet; must hold write_lock."""
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

    async def send_file(self, file_path: str) -> dict[str, Any]:
        """Full client-side session: handshake, manifest, send pieces (compress then encrypt), complete.

        Args:
            file_path: Path to the file to send.

        Returns:
            Transfer summary dict (e.g. transfer_id, filename, status, total_pieces).
        """
        key_manager = KeyManager()
        compressor = Compressor()
        write_lock = asyncio.Lock()
        transfer_id_str = ""
        wire_transfer_id = 0
        manifest = {}

        client_private, client_public = key_manager.generate_keypair()
        salt = key_manager.generate_salt()

        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(self._host, self._port),
            timeout=CONNECTION_TIMEOUT,
        )

        def _send_error(msg: str, wire_id: int) -> None:
            try:
                p = PacketBuilder.build_error(msg, wire_id)
                asyncio.create_task(self._send_packet(writer, p, write_lock))
            except Exception:
                pass

        try:
            # 2. Send HANDSHAKE_INIT
            init_pkt = PacketBuilder.build_handshake_init(client_public, salt)
            await self._send_packet(writer, init_pkt, write_lock)
            logger.info("handshake init sent")

            # 3. Read HANDSHAKE_RESP
            resp_pkt = await asyncio.wait_for(
                FrameReader.read_packet(reader),
                timeout=PACKET_TIMEOUT,
            )
            if resp_pkt.packet_type != PacketType.HANDSHAKE_RESP:
                raise RuntimeError(f"expected HANDSHAKE_RESP, got {resp_pkt.packet_type}")
            resp_body = json.loads(resp_pkt.payload.decode("utf-8"))
            server_public = base64.b64decode(resp_body["public_key"])
            shared = key_manager.derive_shared_secret(client_private, server_public)
            aes_key = key_manager.derive_symmetric_key(shared, salt)
            aes_cipher = AESCipher(aes_key)
            logger.info("handshake complete")

            # 4. Create manifest, save to DB, send MANIFEST
            manifest = TransferManifest.create(file_path)
            transfer_id_str = manifest["transfer_id"]
            wire_transfer_id = _manifest_transfer_id_to_wire(transfer_id_str)
            await self._db_repo.create_transfer(
                transfer_id=transfer_id_str,
                direction="send",
                filename=manifest["filename"],
                file_size=manifest["total_size"],
                total_pieces=manifest["total_pieces"],
                remote_host=f"{self._host}:{self._port}",
                file_hash=manifest["file_hash"],
            )
            manifest_pkt = PacketBuilder.build_manifest(manifest, wire_transfer_id)
            await self._send_packet(writer, manifest_pkt, write_lock)
            logger.info("manifest sent transfer_id={} filename={} pieces={}", transfer_id_str, manifest["filename"], manifest["total_pieces"])

            chunker = FileChunker(file_path)
            total_pieces = manifest["total_pieces"]

            # 5. Loop: read piece blocks, compress, encrypt, send PIECE, wait ACK (retry on NACK)
            for piece in chunker.iter_pieces():
                piece_index = piece["piece_index"]
                piece_data = b"".join(b["block_data"] for b in piece["blocks"])
                compressed = compressor.compress(piece_data)
                encrypted = aes_cipher.encrypt(compressed)
                piece_pkt = PacketBuilder.build_piece(piece_index, encrypted, wire_transfer_id)
                for attempt in range(MAX_PIECE_RETRIES + 1):
                    await self._send_packet(writer, piece_pkt, write_lock)
                    logger.debug("sent PIECE index={} size={}", piece_index, len(encrypted))
                    reply = await asyncio.wait_for(
                        FrameReader.read_packet(reader),
                        timeout=PACKET_TIMEOUT,
                    )
                    if reply.packet_type == PacketType.PIECE_ACK:
                        await self._db_repo.mark_piece_verified(transfer_id_str, piece_index)
                        break
                    if reply.packet_type == PacketType.PIECE_NACK:
                        await self._db_repo.increment_piece_attempts(transfer_id_str, piece_index)
                        if attempt >= MAX_PIECE_RETRIES:
                            raise RuntimeError(f"piece {piece_index} NACK after {MAX_PIECE_RETRIES} retries")
                        continue
                    if reply.packet_type == PacketType.ERROR:
                        err_body = json.loads(reply.payload.decode("utf-8"))
                        raise RuntimeError(err_body.get("message", "server error"))
                    raise RuntimeError(f"expected ACK/NACK, got {reply.packet_type}")

            # 6. Send TRANSFER_COMPLETE
            complete_pkt = Packet(PacketType.TRANSFER_COMPLETE, b"{}", transfer_id=wire_transfer_id)
            await self._send_packet(writer, complete_pkt, write_lock)
            await self._db_repo.update_transfer_status(transfer_id_str, "completed")
            logger.info("transfer complete transfer_id={}", transfer_id_str)

            return {
                "transfer_id": transfer_id_str,
                "filename": manifest["filename"],
                "status": "completed",
                "total_pieces": total_pieces,
                "file_size": manifest["total_size"],
            }

        except asyncio.TimeoutError as e:
            logger.warning("timeout: {}", e)
            try:
                _send_error("timeout", wire_transfer_id)
                if transfer_id_str:
                    await self._db_repo.update_transfer_status(transfer_id_str, "failed")
            except Exception:
                pass
            return {
                "transfer_id": transfer_id_str,
                "filename": manifest.get("filename", ""),
                "status": "failed",
                "error": str(e),
            }
        except Exception as e:
            logger.exception("send_file error: {}", e)
            try:
                _send_error(str(e), wire_transfer_id)
                if transfer_id_str:
                    await self._db_repo.update_transfer_status(transfer_id_str, "failed")
            except Exception:
                pass
            raise
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    async def resume_transfer(self, transfer_id: str, file_path: str) -> dict[str, Any]:
        """Check DB for missing pieces and send only those.

        Args:
            transfer_id: Transfer UUID from original send.
            file_path: Path to the same file (to read piece data).

        Returns:
            Transfer summary dict.
        """
        transfer = await self._db_repo.get_transfer(transfer_id)
        if not transfer:
            raise ValueError(f"transfer not found: {transfer_id}")
        missing = await self._db_repo.get_missing_pieces(transfer_id)
        if not missing:
            await self._db_repo.update_transfer_status(transfer_id, "completed")
            return {
                "transfer_id": transfer_id,
                "filename": transfer.filename,
                "status": "completed",
                "total_pieces": transfer.total_pieces,
                "resumed": True,
            }

        key_manager = KeyManager()
        compressor = Compressor()
        write_lock = asyncio.Lock()
        client_private, client_public = key_manager.generate_keypair()
        salt = key_manager.generate_salt()

        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(self._host, self._port),
            timeout=CONNECTION_TIMEOUT,
        )

        try:
            init_pkt = PacketBuilder.build_handshake_init(client_public, salt)
            await self._send_packet(writer, init_pkt, write_lock)
            resp_pkt = await asyncio.wait_for(
                FrameReader.read_packet(reader),
                timeout=PACKET_TIMEOUT,
            )
            if resp_pkt.packet_type != PacketType.HANDSHAKE_RESP:
                raise RuntimeError(f"expected HANDSHAKE_RESP, got {resp_pkt.packet_type}")
            resp_body = json.loads(resp_pkt.payload.decode("utf-8"))
            server_public = base64.b64decode(resp_body["public_key"])
            shared = key_manager.derive_shared_secret(client_private, server_public)
            aes_key = key_manager.derive_symmetric_key(shared, salt)
            aes_cipher = AESCipher(aes_key)

            wire_transfer_id = _manifest_transfer_id_to_wire(transfer_id)
            manifest = TransferManifest.create(file_path)
            manifest["transfer_id"] = transfer_id
            manifest_pkt = PacketBuilder.build_manifest(manifest, wire_transfer_id)
            await self._send_packet(writer, manifest_pkt, write_lock)

            chunker = FileChunker(file_path)
            pieces_by_index = {p["piece_index"]: p for p in chunker.iter_pieces()}

            for piece_index in missing:
                piece = pieces_by_index.get(piece_index)
                if not piece:
                    raise RuntimeError(f"piece {piece_index} not in file")
                piece_data = b"".join(b["block_data"] for b in piece["blocks"])
                compressed = compressor.compress(piece_data)
                encrypted = aes_cipher.encrypt(compressed)
                piece_pkt = PacketBuilder.build_piece(piece_index, encrypted, wire_transfer_id)
                for attempt in range(MAX_PIECE_RETRIES + 1):
                    await self._send_packet(writer, piece_pkt, write_lock)
                    reply = await asyncio.wait_for(
                        FrameReader.read_packet(reader),
                        timeout=PACKET_TIMEOUT,
                    )
                    if reply.packet_type == PacketType.PIECE_ACK:
                        await self._db_repo.mark_piece_verified(transfer_id, piece_index)
                        break
                    if reply.packet_type == PacketType.PIECE_NACK:
                        await self._db_repo.increment_piece_attempts(transfer_id, piece_index)
                        if attempt >= MAX_PIECE_RETRIES:
                            raise RuntimeError(f"piece {piece_index} NACK after retries")
                        continue
                    if reply.packet_type == PacketType.ERROR:
                        err_body = json.loads(reply.payload.decode("utf-8"))
                        raise RuntimeError(err_body.get("message", "server error"))

            complete_pkt = Packet(PacketType.TRANSFER_COMPLETE, b"{}", transfer_id=wire_transfer_id)
            await self._send_packet(writer, complete_pkt, write_lock)
            await self._db_repo.update_transfer_status(transfer_id, "completed")
            logger.info("resume complete transfer_id={}", transfer_id)
            return {
                "transfer_id": transfer_id,
                "filename": transfer.filename,
                "status": "completed",
                "total_pieces": transfer.total_pieces,
                "resumed": True,
                "missing_sent": len(missing),
            }
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass
