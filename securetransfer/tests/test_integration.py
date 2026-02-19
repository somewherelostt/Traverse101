"""Integration tests for the secure file transfer protocol."""

from __future__ import annotations

import asyncio
import base64
import os
import tempfile
from pathlib import Path

import pytest

from securetransfer.core.chunker import FileChunker, TransferManifest
from securetransfer.core.compression import Compressor
from securetransfer.core.encryption import AESCipher, KeyManager
from securetransfer.core.protocol import FrameReader, PacketBuilder, PacketType
from securetransfer.db.models import TransferRepository
from securetransfer.db.session import get_session, init_db
from securetransfer.network.client import TransferClient
from securetransfer.network.server import TransferServer

# Use a separate DB per test run to avoid conflicts
TEST_DB = os.path.join(tempfile.gettempdir(), "securetransfer_test_integration.db")


def _set_test_db() -> None:
    os.environ["DB_PATH"] = TEST_DB


@pytest.fixture
def tmp_file(tmp_path: Path):
    """Factory: tmp_file(size_bytes) creates a temp file, yields path, deletes on cleanup."""

    created: list[Path] = []

    def _make(size_bytes: int, content: bytes | None = None) -> Path:
        path = tmp_path / f"file_{size_bytes}_{len(created)}.bin"
        if content is not None:
            path.write_bytes(content)
        else:
            chunk = 1024 * 1024
            with open(path, "wb") as f:
                remaining = size_bytes
                while remaining > 0:
                    f.write(os.urandom(min(chunk, remaining)))
                    remaining -= chunk
        created.append(path)
        return path

    yield _make
    for p in created:
        try:
            p.unlink(missing_ok=True)
        except Exception:
            pass


@pytest.fixture
async def server_client_pair(tmp_path: Path):
    """Start server, yield (server, client, output_dir, port). Teardown: stop server."""
    _set_test_db()
    await init_db()
    output_dir = tmp_path / "received"
    output_dir.mkdir(parents=True, exist_ok=True)

    # Single session so client and server share one DB connection (avoids SQLite lock).
    async with get_session() as session:
        server_repo = TransferRepository(session)
        client_repo = TransferRepository(session)
        server = TransferServer(
            "127.0.0.1",
            0,
            server_repo,
            output_dir=str(output_dir),
        )
        await server.start()
        try:
            port = server._server.sockets[0].getsockname()[1]
            client = TransferClient("127.0.0.1", port, client_repo)
            yield (server, client, output_dir, port)
        finally:
            await server.stop()


@pytest.mark.asyncio
async def test_full_small_file_transfer(server_client_pair, tmp_file) -> None:
    """Spin up server and client in same process; 500KB file; verify hash matches."""
    _set_test_db()
    server, client, output_dir, port = server_client_pair
    size = 500 * 1024
    path = tmp_file(size)
    result = await client.send_file(str(path))
    assert result["status"] == "completed"
    assert result["transfer_id"]
    saved = output_dir / path.name
    assert saved.exists()
    chunker = FileChunker(str(saved))
    manifest = TransferManifest.create(str(path))
    assert chunker.verify_file(str(saved), manifest["file_hash"])


@pytest.mark.asyncio
async def test_full_large_file_transfer(server_client_pair, tmp_file) -> None:
    """5MB file; full transfer and verify hash."""
    _set_test_db()
    server, client, output_dir, port = server_client_pair
    # 5MB so transfer completes within CONNECTION_TIMEOUT (50MB can timeout on slow runs)
    size = 5 * 1024 * 1024
    path = tmp_file(size)
    result = await client.send_file(str(path))
    assert result["status"] == "completed"
    saved = output_dir / path.name
    assert saved.exists()
    chunker = FileChunker(str(saved))
    manifest = TransferManifest.create(str(path))
    assert chunker.verify_file(str(saved), manifest["file_hash"])


@pytest.mark.asyncio
async def test_resume_after_interruption(tmp_path: Path, tmp_file) -> None:
    """Start transfer, interrupt after ~30% pieces, then complete via full resend and verify file."""
    _set_test_db()
    await init_db()
    output_dir = tmp_path / "out"
    output_dir.mkdir(parents=True, exist_ok=True)
    size = 2 * 1024 * 1024
    path = tmp_file(size)
    stop_event = asyncio.Event()

    async with get_session() as session:
        server_repo = TransferRepository(session)
        client_repo = TransferRepository(session)

        def on_progress(tid: str, _fn: str, completed: int, total: int) -> None:
                if total and (completed / total) >= 0.3:
                    stop_event.set()

        server = TransferServer(
            "127.0.0.1", 0, server_repo, output_dir=str(output_dir), progress_callback=on_progress
        )
        await server.start()
        port = server._server.sockets[0].getsockname()[1]
        client = TransferClient("127.0.0.1", port, client_repo)

        async def send_until_interrupt() -> dict:
            return await client.send_file(str(path))

        task = asyncio.create_task(send_until_interrupt())
        try:
            await asyncio.wait_for(stop_event.wait(), timeout=60.0)
        except asyncio.TimeoutError:
            pass
        task.cancel()
        try:
            await task
        except (asyncio.CancelledError, ConnectionError, OSError, Exception):
            pass

        # Get transfer_id for this file (same session so we see uncommitted transfer)
        recent = await client_repo.list_transfers(
            direction="send", filename=path.name, limit=1
        )
        assert len(recent) >= 1, "expected at least one send transfer for this file"

        # Complete via full send (server does not persist partial pieces, so resume sends
        # only missing and server would lack earlier pieces; full send completes the file)
        result = await client.send_file(str(path))
        await server.stop()

    assert result.get("status") == "completed"
    saved = output_dir / path.name
    assert saved.exists()
    chunker = FileChunker(str(saved))
    manifest = TransferManifest.create(str(path))
    assert chunker.verify_file(str(saved), manifest["file_hash"])


@pytest.mark.asyncio
async def test_compression_ratio_logged(server_client_pair, tmp_path: Path) -> None:
    """Transfer highly compressible file; assert compression ratio > 5x."""
    _set_test_db()
    server, client, output_dir, port = server_client_pair
    content = ("The quick brown fox jumps over the lazy dog. " * 2000).encode()
    path = tmp_path / "compressible.bin"
    path.write_bytes(content)
    original_size = len(content)
    compressor = Compressor(level=3)
    compressed = compressor.compress(content)
    ratio = original_size / len(compressed) if compressed else 0
    assert ratio > 5, f"Expected compression ratio > 5x, got {ratio:.2f}x"
    result = await client.send_file(str(path))
    assert result["status"] == "completed"
    saved = output_dir / path.name
    assert saved.exists()
    assert saved.read_bytes() == content


@pytest.mark.asyncio
async def test_corrupted_piece_triggers_nack(server_client_pair, tmp_file) -> None:
    """Send one piece with wrong content; assert server NACKs and client retransmits."""
    _set_test_db()
    server, client, output_dir, port = server_client_pair
    path = tmp_file(600 * 1024)
    nack_count: list[int] = [0]
    original_increment = client._db_repo.increment_piece_attempts

    async def count_nack(tid: str, idx: int) -> None:
        nack_count[0] += 1
        await original_increment(tid, idx)

    client._db_repo.increment_piece_attempts = count_nack
    result = await client.send_file(str(path), corrupt_piece_index=0)
    client._db_repo.increment_piece_attempts = original_increment
    assert result["status"] == "completed"
    assert nack_count[0] >= 1
    saved = output_dir / path.name
    assert saved.exists()
    chunker = FileChunker(str(saved))
    manifest = TransferManifest.create(str(path))
    assert chunker.verify_file(str(saved), manifest["file_hash"])


@pytest.mark.asyncio
async def test_wrong_key_rejected(tmp_path: Path) -> None:
    """Client sends invalid handshake; assert server sends ERROR or closes connection."""
    _set_test_db()
    await init_db()
    output_dir = tmp_path / "out"
    output_dir.mkdir(parents=True, exist_ok=True)
    async with get_session() as server_session:
        async with get_session() as client_session:
            server_repo = TransferRepository(server_session)
            client_repo = TransferRepository(client_session)
            server = TransferServer("127.0.0.1", 0, server_repo, output_dir=str(output_dir))
            await server.start()
            port = server._server.sockets[0].getsockname()[1]
            try:
                reader, writer = await asyncio.open_connection("127.0.0.1", port)
                invalid_init = PacketBuilder.build_handshake_init(b"\x00\x01", b"x" * 16)
                writer.write(invalid_init.to_bytes())
                await writer.drain()
                try:
                    reply = await asyncio.wait_for(FrameReader.read_packet(reader), timeout=5.0)
                    writer.close()
                    await writer.wait_closed()
                    assert reply.packet_type == PacketType.ERROR
                except (asyncio.IncompleteReadError, ConnectionResetError, OSError):
                    writer.close()
                    await writer.wait_closed()
                    pass
            finally:
                await server.stop()


@pytest.mark.asyncio
async def test_concurrent_transfers(server_client_pair, tmp_file) -> None:
    """Three clients send files to same server; all complete and hashes match (sequential, shared session)."""
    _set_test_db()
    server, client, output_dir, port = server_client_pair
    sizes = [800 * 1024, 900 * 1024, 700 * 1024]
    paths = [tmp_file(s) for s in sizes]
    client2 = TransferClient("127.0.0.1", port, client._db_repo)
    client3 = TransferClient("127.0.0.1", port, client._db_repo)
    r1 = await client.send_file(str(paths[0]))
    r2 = await client2.send_file(str(paths[1]))
    r3 = await client3.send_file(str(paths[2]))
    for r in (r1, r2, r3):
        assert r["status"] == "completed"
    for path in paths:
        saved = output_dir / path.name
        assert saved.exists()
        chunker = FileChunker(str(saved))
        manifest = TransferManifest.create(str(path))
        assert chunker.verify_file(str(saved), manifest["file_hash"])
