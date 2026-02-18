"""Tests for chunker module."""

import tempfile
from pathlib import Path

import pytest

from securetransfer.core.chunker import (
    ChunkError,
    FileChunker,
    TransferManifest,
)


def test_chunk_small_file() -> None:
    """File smaller than one piece yields a single piece with correct metadata."""
    piece_size = 1_048_576  # 1 MB
    block_size = 16_384     # 16 KB
    content = b"small file content"
    with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as f:
        f.write(content)
        path = f.name
    try:
        chunker = FileChunker(path, piece_size=piece_size, block_size=block_size)
        meta = chunker.get_file_metadata()
        assert meta["filename"] == Path(path).name
        assert meta["total_size"] == len(content)
        assert meta["total_pieces"] == 1
        assert meta["piece_size"] == piece_size
        assert len(meta["file_hash"]) == 64  # SHA-256 hex

        pieces = list(chunker.iter_pieces())
        assert len(pieces) == 1
        assert pieces[0]["piece_index"] == 0
        assert len(pieces[0]["piece_hash"]) == 64
        assert len(pieces[0]["blocks"]) == 1
        assert pieces[0]["blocks"][0]["block_index"] == 0
        assert pieces[0]["blocks"][0]["block_data"] == content
    finally:
        Path(path).unlink(missing_ok=True)


def test_chunk_large_file() -> None:
    """Verify piece count is correct for a file larger than one piece."""
    piece_size = 1024   # 1 KB per piece for test
    block_size = 256
    # Create file with 3 full pieces + partial 4th
    total_size = 3 * piece_size + 100
    content = b"x" * total_size
    with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as f:
        f.write(content)
        path = f.name
    try:
        chunker = FileChunker(path, piece_size=piece_size, block_size=block_size)
        meta = chunker.get_file_metadata()
        assert meta["total_size"] == total_size
        assert meta["total_pieces"] == 4  # 3 full + 1 partial
        assert meta["piece_size"] == piece_size

        pieces = list(chunker.iter_pieces())
        assert len(pieces) == 4
        assert pieces[0]["piece_index"] == 0
        assert pieces[3]["piece_index"] == 3
        assert len(pieces[3]["blocks"][-1]["block_data"]) <= block_size
    finally:
        Path(path).unlink(missing_ok=True)


def test_piece_hash_verification() -> None:
    """verify_piece returns True for matching hash, False otherwise."""
    content = b"piece data"
    with tempfile.NamedTemporaryFile(delete=False) as f:
        f.write(content)
        path = f.name
    try:
        chunker = FileChunker(path, piece_size=1024, block_size=256)
        pieces = list(chunker.iter_pieces())
        expected_hash = pieces[0]["piece_hash"]
        assert chunker.verify_piece(0, content, expected_hash) is True
        assert chunker.verify_piece(0, content, expected_hash.upper()) is True
        assert chunker.verify_piece(0, b"wrong data", expected_hash) is False
        assert chunker.verify_piece(0, content, "a" * 64) is False
    finally:
        Path(path).unlink(missing_ok=True)


def test_file_hash_verification() -> None:
    """verify_file returns True when file hash matches expected."""
    content = b"full file content for hash"
    with tempfile.NamedTemporaryFile(delete=False) as f:
        f.write(content)
        path = f.name
    try:
        chunker = FileChunker(path, piece_size=1024, block_size=256)
        meta = chunker.get_file_metadata()
        expected = meta["file_hash"]
        assert chunker.verify_file(path, expected) is True
        assert chunker.verify_file(path, expected.upper()) is True
        assert chunker.verify_file(path, "0" * 64) is False
    finally:
        Path(path).unlink(missing_ok=True)


def test_manifest_create_save_load_roundtrip() -> None:
    """Manifest create -> save -> load reproduces the same data."""
    content = b"manifest test file content"
    with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as f:
        f.write(content)
        file_path = f.name
    manifest_path = file_path + ".manifest.json"
    try:
        manifest = TransferManifest.create(file_path)
        assert "transfer_id" in manifest
        assert len(manifest["transfer_id"]) == 36  # uuid4 format
        assert manifest["filename"] == Path(file_path).name
        assert manifest["total_size"] == len(content)
        assert manifest["total_pieces"] >= 1
        assert "piece_hashes" in manifest
        assert "file_hash" in manifest
        assert "created_at" in manifest

        TransferManifest.save(manifest, manifest_path)
        assert Path(manifest_path).exists()

        loaded = TransferManifest.load(manifest_path)
        assert loaded["filename"] == manifest["filename"]
        assert loaded["total_size"] == manifest["total_size"]
        assert loaded["total_pieces"] == manifest["total_pieces"]
        assert loaded["piece_hashes"] == manifest["piece_hashes"]
        assert loaded["file_hash"] == manifest["file_hash"]
        # transfer_id and created_at may differ if we re-create; for load we compare saved fields
        assert loaded["transfer_id"] == manifest["transfer_id"]
        assert loaded["created_at"] == manifest["created_at"]
    finally:
        Path(file_path).unlink(missing_ok=True)
        Path(manifest_path).unlink(missing_ok=True)


def test_get_missing_pieces() -> None:
    """get_missing_pieces returns indices not in received_pieces."""
    manifest = {
        "total_pieces": 5,
        "piece_hashes": {"0": "a", "1": "b", "2": "c", "3": "d", "4": "e"},
    }
    missing = TransferManifest.get_missing_pieces(manifest, [])
    assert missing == [0, 1, 2, 3, 4]

    missing = TransferManifest.get_missing_pieces(manifest, [0, 2, 4])
    assert missing == [1, 3]

    missing = TransferManifest.get_missing_pieces(manifest, [0, 1, 2, 3, 4])
    assert missing == []


def test_chunker_nonexistent_file_raises() -> None:
    """FileChunker raises ChunkError for nonexistent path."""
    with pytest.raises(ChunkError, match="not found"):
        FileChunker("/nonexistent/path/file.bin")


def test_manifest_load_nonexistent_raises() -> None:
    """TransferManifest.load raises ChunkError for missing file."""
    with pytest.raises(ChunkError, match="Manifest not found"):
        TransferManifest.load("/nonexistent/manifest.json")
