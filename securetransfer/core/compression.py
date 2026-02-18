"""Compression module using zstandard."""

from __future__ import annotations

import math
import time
from collections import Counter
from pathlib import Path

import zstandard as zstd
from loguru import logger


class CompressorError(Exception):
    """Raised when compression or decompression fails (e.g. corrupted data, I/O)."""

    pass


def estimate_compressibility(data: bytes) -> float:
    """Estimate how compressible the data is using Shannon entropy.

    Returns a score in [0, 1]. Higher means more compressible (structured/repetitive).
    If score < 0.1, data is likely already compressed (e.g. JPEG, MP4, zip)
    and compressing it further would waste CPU.

    Args:
        data: Raw bytes to analyze.

    Returns:
        Compressibility ratio in range 0.0 to 1.0.
    """
    if not data:
        return 0.0
    length = len(data)
    counts = Counter(data)
    entropy = 0.0
    for count in counts.values():
        p = count / length
        if p > 0:
            entropy -= p * math.log2(p)
    # Max entropy for bytes is 8 bits; normalize to [0,1]
    # Compressibility = 1 - normalized_entropy (low entropy => high compressibility)
    normalized = entropy / 8.0
    return float(max(0.0, min(1.0, 1.0 - normalized)))


# Threshold below which we consider data already compressed (skip compression)
COMPRESSIBILITY_THRESHOLD = 0.1


class Compressor:
    """Zstandard compressor for in-memory and streaming operations."""

    def __init__(self, level: int = 3) -> None:
        """Initialize compressor with compression level.

        Args:
            level: Compression level 1-22. Default 3 favors speed over ratio.
        """
        if not 1 <= level <= 22:
            raise ValueError("level must be between 1 and 22")
        self._level = level
        self._compressor = zstd.ZstdCompressor(level=level)
        self._decompressor = zstd.ZstdDecompressor()

    def compress(self, data: bytes) -> bytes:
        """Compress bytes in memory.

        Args:
            data: Raw bytes to compress.

        Returns:
            Compressed bytes.

        Raises:
            CompressorError: On compression failure (e.g. corrupted or empty handling).
        """
        if not data:
            logger.warning("compress called with empty data")
            return b""
        try:
            start = time.perf_counter()
            out = self._compressor.compress(data)
            elapsed_ms = (time.perf_counter() - start) * 1000
            score = estimate_compressibility(data)
            if score < COMPRESSIBILITY_THRESHOLD:
                logger.debug(
                    "compressed already-compressible data (score={:.3f}); "
                    "consider skipping compression",
                    score,
                )
            logger.debug(
                "compress: {} -> {} bytes in {:.2f} ms",
                len(data),
                len(out),
                elapsed_ms,
            )
            return out
        except Exception as e:
            logger.exception("compress failed")
            raise CompressorError("Compression failed") from e

    def decompress(self, data: bytes) -> bytes:
        """Decompress bytes in memory.

        Args:
            data: Compressed bytes (zstd frame).

        Returns:
            Decompressed bytes.

        Raises:
            CompressorError: On decompression failure (e.g. corrupted data).
        """
        if not data:
            logger.warning("decompress called with empty data")
            return b""
        try:
            start = time.perf_counter()
            out = self._decompressor.decompress(data)
            elapsed_ms = (time.perf_counter() - start) * 1000
            logger.debug(
                "decompress: {} -> {} bytes in {:.2f} ms",
                len(data),
                len(out),
                elapsed_ms,
            )
            return out
        except zstd.ZstdError as e:
            logger.exception("decompress failed: corrupted or invalid zstd data")
            raise CompressorError("Decompression failed: corrupted or invalid data") from e

    def compress_stream(self, input_path: str, output_path: str) -> dict:
        """Compress a file to another file using streaming.

        Args:
            input_path: Path to source file.
            output_path: Path to write compressed file.

        Returns:
            Dict with keys: original_size, compressed_size, ratio, time_ms.

        Raises:
            CompressorError: If input file not found or write/read fails.
        """
        inp = Path(input_path)
        if not inp.exists():
            logger.error("compress_stream: file not found: {}", input_path)
            raise CompressorError(f"File not found: {input_path}")
        start = time.perf_counter()
        try:
            with open(inp, "rb") as f_in:
                original_size = inp.stat().st_size
                if original_size == 0:
                    logger.warning("compress_stream: empty file {}", input_path)
                    with open(output_path, "wb") as f_out:
                        pass
                    elapsed_ms = (time.perf_counter() - start) * 1000
                    return {
                        "original_size": 0,
                        "compressed_size": 0,
                        "ratio": 0.0,
                        "time_ms": round(elapsed_ms, 2),
                    }
                with open(output_path, "wb") as f_out:
                    cctx = zstd.ZstdCompressor(level=self._level)
                    writer = cctx.stream_writer(f_out)
                    read = 0
                    chunk_size = 1024 * 1024
                    while True:
                        chunk = f_in.read(chunk_size)
                        if not chunk:
                            break
                        read += len(chunk)
                        writer.write(chunk)
                    writer.close()
            compressed_size = Path(output_path).stat().st_size
            ratio = compressed_size / original_size if original_size else 0.0
            elapsed_ms = (time.perf_counter() - start) * 1000
            logger.info(
                "compress_stream: {} -> {} ({} -> {} bytes, ratio={:.4f}) in {:.2f} ms",
                input_path,
                output_path,
                original_size,
                compressed_size,
                ratio,
                elapsed_ms,
            )
            return {
                "original_size": original_size,
                "compressed_size": compressed_size,
                "ratio": round(ratio, 4),
                "time_ms": round(elapsed_ms, 2),
            }
        except zstd.ZstdError as e:
            logger.exception("compress_stream failed")
            raise CompressorError("Stream compression failed") from e
        except OSError as e:
            logger.exception("compress_stream I/O error")
            raise CompressorError(f"Stream compression I/O failed: {e}") from e

    def decompress_stream(self, input_path: str, output_path: str) -> dict:
        """Decompress a file to another file using streaming.

        Args:
            input_path: Path to compressed file.
            output_path: Path to write decompressed file.

        Returns:
            Dict with keys: original_size, compressed_size, ratio, time_ms
            (original_size = compressed file size, compressed_size = decompressed size).

        Raises:
            CompressorError: If input file not found or data corrupted.
        """
        inp = Path(input_path)
        if not inp.exists():
            logger.error("decompress_stream: file not found: {}", input_path)
            raise CompressorError(f"File not found: {input_path}")
        start = time.perf_counter()
        try:
            compressed_size = inp.stat().st_size
            if compressed_size == 0:
                logger.warning("decompress_stream: empty file {}", input_path)
                with open(output_path, "wb") as f_out:
                    pass
                elapsed_ms = (time.perf_counter() - start) * 1000
                return {
                    "original_size": 0,
                    "compressed_size": 0,
                    "ratio": 0.0,
                    "time_ms": round(elapsed_ms, 2),
                }
            with open(inp, "rb") as f_in:
                with open(output_path, "wb") as f_out:
                    dctx = zstd.ZstdDecompressor()
                    reader = dctx.stream_reader(f_in)
                    decompressed = reader.readall()
                    f_out.write(decompressed)
            original_size = compressed_size
            decompressed_size = len(decompressed)
            ratio = original_size / decompressed_size if decompressed_size else 0.0
            elapsed_ms = (time.perf_counter() - start) * 1000
            logger.info(
                "decompress_stream: {} -> {} ({} -> {} bytes) in {:.2f} ms",
                input_path,
                output_path,
                original_size,
                decompressed_size,
                elapsed_ms,
            )
            return {
                "original_size": original_size,
                "compressed_size": decompressed_size,
                "ratio": round(ratio, 4),
                "time_ms": round(elapsed_ms, 2),
            }
        except zstd.ZstdError as e:
            logger.exception("decompress_stream failed: corrupted or invalid zstd data")
            raise CompressorError("Decompression failed: corrupted or invalid data") from e
        except OSError as e:
            logger.exception("decompress_stream I/O error")
            raise CompressorError(f"Stream decompression I/O failed: {e}") from e
