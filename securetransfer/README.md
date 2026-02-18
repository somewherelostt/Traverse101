# SecureTransfer

A production-grade Python project for secure file transfer.

## Features
- **Compression**: Zstd compression
- **Encryption**: AES-256-GCM + X25519 key exchange
- **Chunking**: Efficient file chunking and hashing
- **Protocol**: Custom packet framing
- **Network**: Asyncio TCP server and client
- **Database**: SQLite with SQLAlchemy

## Installation

```bash
pip install -r requirements.txt
pip install -e .
```

## Configuration

Copy `.env.example` to `.env` and adjust the values:

```bash
cp .env.example .env
```

## Usage

(TODO: Add usage instructions)

## Development

Run tests:

```bash
pytest
```
