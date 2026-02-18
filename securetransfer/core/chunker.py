"""File chunking and hashing module for resumable secure transfer."""

from __future__ import annotations

import hashlib
import json
import math
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Generator

# Default sizes: 1 MB per piece, 16 KB per block
DEFAULT_PIECE_SIZE = 1_048_576
DEFAULT_BLOCK_SIZE = 16_384


# --- Exceptions --------------------------------------------------------------


class ChunkError(Exception):
    """Raised when chunking or piece/block operations fail."""

    pass


class HashMismatchError(Exception):
    """Raised when a computed hash does not match the expected value."""

    pass


# --- FileChunker --------------------------------------------------------------


class FileChunker:
    """Splits a file into fixed-size pieces and blocks with SHA-256 hashes."""

    def __init__(
        self,
        file_path: str,
        piece_size: int = DEFAULT_PIECE_SIZE,
        block_size: int = DEFAULT_BLOCK_SIZE,
    ) -> None:
        """Initialize chunker for a file.

        Args:
            file_path: Path to the file to chunk.
            piece_size: Size of each piece in bytes (default 1 MiB).
            block_size: Size of each block within a piece in bytes (default 16 KiB).

        Raises:
            ChunkError: If file does not exist or is not a file.
        """
        self._path = Path(file_path)
        if not self._path.exists():
            raise ChunkError(f"File not found: {file_path}")
        if not self._path.is_file():
            raise ChunkError(f"Not a file: {file_path}")
        if piece_size <= 0 or block_size <= 0:
            raise ChunkError("piece_size and block_size must be positive")
        if block_size > piece_size:
            raise ChunkError("block_size must not exceed piece_size")
        self._piece_size = piece_size
        self._block_size = block_size
        self._total_size = self._path.stat().st_size

    def _compute_file_hash(self) -> str:
        """Compute SHA-256 of the entire file by streaming."""
        hasher = hashlib.sha256()
        with open(self._path, "rb") as f:
            while True:
                chunk = f.read(self._block_size)
                if not chunk:
                    break
                hasher.update(chunk)
        return hasher.hexdigest()

    def get_file_metadata(self) -> dict[str, Any]:
        """Return metadata describing the file and its piece layout.

        Returns:
            Dict with: filename, total_size, total_pieces, piece_size, file_hash (SHA-256 hex).
        """
        total_pieces = math.ceil(self._total_size / self._piece_size) if self._total_size else 0
        file_hash = self._compute_file_hash()
        return {
            "filename": self._path.name,
            "total_size": self._total_size,
            "total_pieces": total_pieces,
            "piece_size": self._piece_size,
            "file_hash": file_hash,
        }

    def iter_pieces(self) -> Generator[dict[str, Any], None, None]:
        """Yield each piece with its index, SHA-256 hash, and blocks.

        Yields:
            Dict with: piece_index (int), piece_hash (str, SHA-256 hex),
            blocks (list of {block_index, block_data}).
        """
        total_pieces = math.ceil(self._total_size / self._piece_size) if self._total_size else 0
        with open(self._path, "rb") as f:
            for piece_index in range(total_pieces):
                piece_data = f.read(self._piece_size)
                if not piece_data:
                    break
                piece_hash = hashlib.sha256(piece_data).hexdigest()
                blocks: list[dict[str, Any]] = []
                offset = 0
                block_index = 0
                while offset < len(piece_data):
                    block_data = piece_data[offset : offset + self._block_size]
                    blocks.append({"block_index": block_index, "block_data": block_data})
                    offset += len(block_data)
                    block_index += 1
                yield {
                    "piece_index": piece_index,
                    "piece_hash": piece_hash,
                    "blocks": blocks,
                }

    def verify_piece(
        self,
        piece_index: int,
        data: bytes,
        expected_hash: str,
    ) -> bool:
        """Verify that the given data matches the expected piece hash.

        Args:
            piece_index: Index of the piece (for error messages; not used in comparison).
            data: Raw piece data.
            expected_hash: Expected SHA-256 hash as hex string.

        Returns:
            True if SHA-256(data) equals expected_hash (case-insensitive).
        """
        actual = hashlib.sha256(data).hexdigest().lower()
        expected = expected_hash.strip().lower()
        return actual == expected

    def verify_file(self, file_path: str, expected_hash: str) -> bool:
        """Verify that the file at file_path has the given SHA-256 hash.

        Args:
            file_path: Path to the file to verify.
            expected_hash: Expected SHA-256 hash of the entire file (hex string).

        Returns:
            True if the file's SHA-256 matches expected_hash (case-insensitive).
        """
        path = Path(file_path)
        if not path.exists() or not path.is_file():
            raise ChunkError(f"File not found or not a file: {file_path}")
        hasher = hashlib.sha256()
        with open(path, "rb") as f:
            while True:
                chunk = f.read(self._block_size)
                if not chunk:
                    break
                hasher.update(chunk)
        actual = hasher.hexdigest().lower()
        expected = expected_hash.strip().lower()
        return actual == expected


# --- TransferManifest --------------------------------------------------------


class TransferManifest:
    """Describes a file transfer for resume support (piece hashes and metadata)."""

    @staticmethod
    def create(file_path: str) -> dict[str, Any]:
        """Build a JSON-serializable manifest for the given file.

        Args:
            file_path: Path to the file.

        Returns:
            Dict with: transfer_id (uuid4), filename, total_size, total_pieces,
            piece_hashes (dict piece_index -> sha256 hex; keys are strings for JSON),
            file_hash, created_at (ISO 8601).
        """
        chunker = FileChunker(file_path)
        metadata = chunker.get_file_metadata()
        piece_hashes: dict[str, str] = {}
        for piece in chunker.iter_pieces():
            piece_hashes[str(piece["piece_index"])] = piece["piece_hash"]
        return {
            "transfer_id": str(uuid.uuid4()),
            "filename": metadata["filename"],
            "total_size": metadata["total_size"],
            "total_pieces": metadata["total_pieces"],
            "piece_hashes": piece_hashes,
            "file_hash": metadata["file_hash"],
            "created_at": datetime.now(tz=timezone.utc).isoformat(),
        }

    @staticmethod
    def save(manifest: dict[str, Any], path: str) -> None:
        """Write manifest to a JSON file.

        Args:
            manifest: Manifest dict from create() or load().
            path: Output file path.

        Raises:
            ChunkError: On I/O failure.
        """
        try:
            Path(path).write_text(
                json.dumps(manifest, indent=2),
                encoding="utf-8",
            )
        except OSError as e:
            raise ChunkError(f"Failed to save manifest: {e}") from e

    @staticmethod
    def load(path: str) -> dict[str, Any]:
        """Load manifest from a JSON file.

        Args:
            path: Path to the manifest JSON file.

        Returns:
            Manifest dict (piece_hashes keys are strings).

        Raises:
            ChunkError: If file not found or invalid JSON.
        """
        p = Path(path)
        if not p.exists():
            raise ChunkError(f"Manifest not found: {path}")
        try:
            return json.loads(p.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as e:
            raise ChunkError(f"Failed to load manifest: {e}") from e

    @staticmethod
    def get_missing_pieces(
        manifest: dict[str, Any],
        received_pieces: list[int],
    ) -> list[int]:
        """Return piece indices that are not in received_pieces (for resume).

        Args:
            manifest: Manifest from create() or load().
            received_pieces: List of piece indices already received.

        Returns:
            Sorted list of piece indices still missing (0 to total_pieces - 1).
        """
        total = int(manifest["total_pieces"])
        received_set = set(received_pieces)
        return sorted(i for i in range(total) if i not in received_set)
