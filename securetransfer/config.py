"""Configuration loaded from environment with validation.

All settings have sane defaults. Call validate() on startup to enforce
constraints (port range, chunk size power of 2, etc.).
"""

from __future__ import annotations

import os
from pathlib import Path


def _env_int(key: str, default: int) -> int:
    val = os.getenv(key)
    if val is None:
        return default
    try:
        return int(val)
    except ValueError:
        return default


def _env_str(key: str, default: str) -> str:
    return os.getenv(key, default)


# --- Server / Network --------------------------------------------------------
HOST = _env_str("ST_HOST", "0.0.0.0")
PORT = _env_int("ST_PORT", 9000)
CONNECTION_TIMEOUT = _env_int("ST_CONNECTION_TIMEOUT", 30)
PACKET_TIMEOUT = _env_int("ST_PACKET_TIMEOUT", 10)

# Rate limiting (server)
MAX_CONCURRENT_CONNECTIONS_PER_IP = _env_int("ST_MAX_CONCURRENT_PER_IP", 5)
RATE_LIMIT_BYTES_PER_SEC = _env_int("ST_RATE_LIMIT_BYTES_PER_SEC", 10 * 1024 * 1024)  # 10 MB/s
FAILED_HANDSHAKE_BAN_THRESHOLD = _env_int("ST_FAILED_HANDSHAKE_BAN_THRESHOLD", 3)
FAILED_HANDSHAKE_BAN_WINDOW_SEC = _env_int("ST_FAILED_HANDSHAKE_BAN_WINDOW_SEC", 60)

# Security
MAX_TRANSFER_SIZE = _env_int("ST_MAX_TRANSFER_SIZE", 10 * 1024 * 1024 * 1024)  # 10 GB default
MAX_PAYLOAD_SIZE = _env_int("ST_MAX_PAYLOAD_SIZE", 64 * 1024 * 1024)  # 64 MB per packet

# --- Chunking / Transfer ------------------------------------------------------
CHUNK_SIZE = _env_int("ST_CHUNK_SIZE", 1 * 1024 * 1024)  # 1 MB
BLOCK_SIZE = _env_int("ST_BLOCK_SIZE", 16 * 1024)  # 16 KB
COMPRESSION_LEVEL = _env_int("ST_COMPRESSION_LEVEL", 3)

# --- Database & Logging -------------------------------------------------------
DB_PATH = _env_str("DB_PATH", "securetransfer.db")
LOG_LEVEL = _env_str("LOG_LEVEL", "INFO")
LOG_PATH = _env_str("ST_LOG_PATH", "logs/securetransfer.log")
LOG_ROTATION = _env_str("ST_LOG_ROTATION", "10 MB")
LOG_RETENTION = _env_str("ST_LOG_RETENTION", "7 days")


class ConfigError(Exception):
    """Raised when config validation fails."""

    pass


def validate() -> None:
    """Validate configuration. Call on startup.

    Raises:
        ConfigError: If any constraint is violated.
    """
    if not (1024 <= PORT <= 65535):
        raise ConfigError(
            f"PORT must be in 1024-65535, got {PORT}. "
            "Set ST_PORT environment variable."
        )
    # Chunk size must be power of 2 (for alignment and buffer sizing)
    if CHUNK_SIZE <= 0 or (CHUNK_SIZE & (CHUNK_SIZE - 1)) != 0:
        raise ConfigError(
            f"CHUNK_SIZE must be a positive power of 2, got {CHUNK_SIZE}. "
            "Set ST_CHUNK_SIZE environment variable."
        )
    if BLOCK_SIZE <= 0 or (BLOCK_SIZE & (BLOCK_SIZE - 1)) != 0:
        raise ConfigError(
            f"BLOCK_SIZE must be a positive power of 2, got {BLOCK_SIZE}. "
            "Set ST_BLOCK_SIZE environment variable."
        )
    if MAX_TRANSFER_SIZE <= 0:
        raise ConfigError(
            f"MAX_TRANSFER_SIZE must be positive, got {MAX_TRANSFER_SIZE}."
        )
    if MAX_PAYLOAD_SIZE <= 0 or MAX_PAYLOAD_SIZE > 128 * 1024 * 1024:
        raise ConfigError(
            f"MAX_PAYLOAD_SIZE must be in (0, 128MB], got {MAX_PAYLOAD_SIZE}."
        )
    if MAX_CONCURRENT_CONNECTIONS_PER_IP < 1:
        raise ConfigError("ST_MAX_CONCURRENT_PER_IP must be >= 1.")
    if RATE_LIMIT_BYTES_PER_SEC < 1:
        raise ConfigError("ST_RATE_LIMIT_BYTES_PER_SEC must be >= 1.")


def configure_logging() -> None:
    """Configure loguru: file sink with rotation (max 10 MB per file, keep 7 days)."""
    import sys

    from loguru import logger

    logger.remove()
    logger.add(sys.stderr, level=LOG_LEVEL)
    log_path = Path(LOG_PATH)
    log_path.parent.mkdir(parents=True, exist_ok=True)
    logger.add(
        str(log_path),
        level=LOG_LEVEL,
        rotation=LOG_ROTATION,
        retention=LOG_RETENTION,
    )
