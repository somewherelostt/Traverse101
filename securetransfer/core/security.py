"""Security utilities: path traversal prevention, timing-safe comparison, zeroing.

- Path traversal prevention: sanitize filenames from manifests (e.g. ../../../etc/passwd).
- Timing attack resistance: use hmac.compare_digest for hash/secret comparison.
- Zero-out sensitive bytes (shared secrets, AES keys) after use via ctypes.
"""

from __future__ import annotations

import hmac
from typing import Union

# Use ctypes to zero memory in place (no external libs).
import ctypes


def sanitize_filename(filename: str) -> str:
    """Sanitize filename from manifest to prevent path traversal.

    Rejects or normalizes names that could escape the receive directory
    (e.g. ../../../etc/passwd). Returns a safe basename-only style name.

    Path traversal prevention: never use client-provided paths directly;
    always derive a safe basename and write under server-controlled output_dir.
    """
    if not filename or not filename.strip():
        return "unnamed"
    # Normalize to single forward slashes and strip leading/trailing
    normalized = filename.replace("\\", "/").strip()
    # Remove any path components; keep only the last segment (basename)
    parts = [p for p in normalized.split("/") if p and p.strip()]
    if not parts:
        return "unnamed"
    basename = parts[-1]
    # Remove null bytes and other dangerous chars
    basename = basename.replace("\x00", "")
    # Disallow parent directory segments in the final segment
    if ".." in basename or basename.startswith(".") and basename != ".":
        basename = basename.replace("..", "").lstrip(".")
    if not basename:
        return "unnamed"
    # Limit length to avoid filesystem issues
    if len(basename) > 255:
        basename = basename[:255]
    return basename


def secure_compare(a: Union[bytes, str], b: Union[bytes, str]) -> bool:
    """Constant-time comparison for hashes/secrets.

    Timing attack resistance: use hmac.compare_digest so comparison time
    does not leak information about the content of the operands.
    """
    if isinstance(a, str):
        a = a.encode("utf-8")
    if isinstance(b, str):
        b = b.encode("utf-8")
    return hmac.compare_digest(a, b)


def zero_out_sensitive(buf: bytearray) -> None:
    """Overwrite buffer with zeros in place. Use for shared secrets and AES keys.

    Call this after use so sensitive material is not left in process memory.
    Pass a mutable bytearray (e.g. bytearray(shared_secret)).
    """
    n = len(buf)
    if n == 0:
        return
    arr = (ctypes.c_char * n).from_buffer(buf)
    ctypes.memset(ctypes.addressof(arr), 0, n)
