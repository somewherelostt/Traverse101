"""Tests for compression module."""

import os
import tempfile
from pathlib import Path

import pytest

from securetransfer.core.compression import (
    COMPRESSIBILITY_THRESHOLD,
    Compressor,
    CompressorError,
    estimate_compressibility,
)


def test_compress_decompress_roundtrip() -> None:
    """Compressing then decompressing returns original data."""
    compressor = Compressor(level=3)
    data = b"Hello, world! " * 100
    compressed = compressor.compress(data)
    assert isinstance(compressed, bytes)
    assert len(compressed) < len(data)
    decompressed = compressor.decompress(compressed)
    assert decompressed == data


def test_compress_empty_bytes() -> None:
    """Empty input returns empty bytes; decompress of empty is empty."""
    compressor = Compressor(level=3)
    compressed = compressor.compress(b"")
    assert compressed == b""
    decompressed = compressor.decompress(b"")
    assert decompressed == b""


def test_incompressible_data_detection() -> None:
    """estimate_compressibility returns low score for high-entropy (already compressed) data."""
    # High-entropy data (e.g. random or already compressed) has low compressibility score
    random_like = os.urandom(1024)
    score_random = estimate_compressibility(random_like)
    assert 0 <= score_random <= 1
    # Random data should have low compressibility (high entropy)
    assert score_random < COMPRESSIBILITY_THRESHOLD or score_random < 0.2

    # Highly repetitive data should have high compressibility
    repetitive = b"x" * 1024
    score_rep = estimate_compressibility(repetitive)
    assert score_rep > 0.9

    # Empty returns 0
    assert estimate_compressibility(b"") == 0.0


def test_stream_compress_decompress() -> None:
    """Stream compress and decompress roundtrip and return correct stats."""
    compressor = Compressor(level=3)
    content = b"stream test data " * 500
    with tempfile.TemporaryDirectory() as tmp:
        src = Path(tmp) / "source.bin"
        src.write_bytes(content)
        compressed_path = Path(tmp) / "out.zst"
        result_compress = compressor.compress_stream(str(src), str(compressed_path))
        assert result_compress["original_size"] == len(content)
        assert result_compress["compressed_size"] <= len(content)
        assert 0 <= result_compress["ratio"] <= 1
        assert result_compress["time_ms"] >= 0

        out_path = Path(tmp) / "decompressed.bin"
        result_decompress = compressor.decompress_stream(
            str(compressed_path), str(out_path)
        )
        assert result_decompress["original_size"] == result_compress["compressed_size"]
        assert result_decompress["compressed_size"] == len(content)
        assert out_path.read_bytes() == content


def test_compressor_init_invalid_level() -> None:
    """Compressor rejects level outside 1-22."""
    with pytest.raises(ValueError, match="level must be between 1 and 22"):
        Compressor(level=0)
    with pytest.raises(ValueError, match="level must be between 1 and 22"):
        Compressor(level=23)


def test_file_not_found_raises() -> None:
    """compress_stream and decompress_stream raise CompressorError when file missing."""
    compressor = Compressor(level=3)
    with tempfile.NamedTemporaryFile(delete=True) as f:
        out_path = f.name
    # Ensure file is gone
    assert not os.path.exists(out_path)
    with pytest.raises(CompressorError, match="File not found"):
        compressor.compress_stream("/nonexistent/path/source.bin", out_path)
    with pytest.raises(CompressorError, match="File not found"):
        compressor.decompress_stream("/nonexistent/path/source.zst", out_path)


def test_corrupted_data_raises_compressor_error() -> None:
    """Decompressing invalid/corrupted zstd data raises CompressorError."""
    compressor = Compressor(level=3)
    with pytest.raises(CompressorError, match="Decompression failed"):
        compressor.decompress(b"not valid zstd data")
    with pytest.raises(CompressorError, match="corrupted or invalid"):
        compressor.decompress(b"\x00\x01\x02\x03\x04\x05")