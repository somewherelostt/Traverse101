import os

# Constants
CHUNK_SIZE = 1 * 1024 * 1024  # 1MB
BLOCK_SIZE = 16 * 1024        # 16KB
COMPRESSION_LEVEL = 3

# Configuration
DB_PATH = os.getenv("DB_PATH", "securetransfer.db")
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")
