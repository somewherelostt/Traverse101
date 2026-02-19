# SecureTransfer

A production-grade secure file transfer protocol with compression, encryption, rate limiting, and audit logging.

## Features

- **Compression**: Zstd (whole-payload compression before encryption to prevent CRIME-style leakage)
- **Encryption**: AES-256-GCM + X25519 ECDH (ephemeral keys for forward secrecy)
- **Rate limiting**: Max concurrent per IP, token bucket per connection, ban after failed handshakes
- **Security**: Validated packet fields, max transfer size, path-traversal-safe filenames, timing-safe hash comparison, zeroing of sensitive bytes
- **Audit**: AuditLog for connections, handshakes, transfers, errors, bans; loguru rotation (10 MB / 7 days)
- **Database**: SQLite with SQLAlchemy (transfers, piece status, audit log)

---

## Quick start

### Docker (recommended)

```bash
cd securetransfer
docker compose up --build
# Server listens on 0.0.0.0:9000; received files in volume received_data, logs in server_logs
```

Send a file from another host:

```bash
securetransfer send --host <server-ip> --port 9000 --file /path/to/file
```

### Pip install

```bash
pip install -r requirements.txt
pip install -e .
```

Start the server:

```bash
securetransfer receive --host 0.0.0.0 --port 9000 --output-dir ./received
```

---

## CLI usage

All commands are available via the `securetransfer` entrypoint.

| Command   | Description                    |
|----------|--------------------------------|
| `send`   | Send a file to a remote server |
| `receive`| Start server and receive files |
| `status` | Show transfer status from DB   |
| `resume` | Resume a failed transfer       |
| `keygen` | Generate X25519 keypair        |

### Examples

```bash
# Generate keys (optional; server uses ephemeral keys per session)
securetransfer keygen --output ./keys --password "your-password"

# Send a file
securetransfer send --host 192.168.1.10 --port 9000 --file ./myfile.zip
securetransfer send --host server.example.com --port 9000 --file ./data.bin --compression-level 6

# Start receive server (validates config on startup)
securetransfer receive --host 0.0.0.0 --port 9000 --output-dir ./received

# Show transfer status
securetransfer status --transfer-id <uuid>
securetransfer status --all

# Resume a failed transfer
securetransfer resume --transfer-id <uuid> --host 192.168.1.10 --port 9000 --file ./myfile.zip
```

---

## Security model

**Cryptography and forward secrecy:** The protocol uses X25519 for key agreement and AES-256-GCM for bulk encryption. The server generates a new ephemeral keypair for each connection; keys are never reused across sessions. This provides forward secrecy: compromise of long-term material does not reveal past session keys. The shared secret and derived AES key are zeroed in memory after use. Compression is applied to the whole payload before encryption to avoid CRIME-style leakage; nonces are never reused (12-byte random nonce per encrypt). Hash comparisons use constant-time `hmac.compare_digest` to resist timing attacks.

**Operational hardening:** The server enforces rate limits (max 5 concurrent connections per IP, 10 MB/s per connection via a token bucket, and IP ban after 3 failed handshakes within 60 seconds). All packet fields are validated (no negative or oversized payloads); a configurable maximum transfer size (default 10 GB) is enforced. Filenames from the manifest are sanitized to prevent path traversal (e.g. `../../../etc/passwd`). Connections, handshakes, transfers, errors, and bans are recorded in an audit log with rotation (10 MB per file, 7-day retention).

---

## Architecture (ASCII)

```
+------------------+                    +------------------+
|  Client (send)   |                    |  Server (receive)|
|                  |   TCP (asyncio)     |                  |
|  FileChunker     |--------------------|  Rate limiter    |
|  Compressor      |  HANDSHAKE_INIT    |  (per-IP, token  |
|  AESCipher       |  HANDSHAKE_RESP    |   bucket, ban)    |
|  PacketBuilder   |  MANIFEST          |  ThrottledReader |
|  TransferClient  |  PIECE / ACK/NACK  |  KeyManager      |
|                  |  TRANSFER_COMPLETE |  AESCipher       |
|  TransferRepository (SQLite)           |  TransferRepository|
|                  |                    |  AuditLog       |
+------------------+                    +------------------+
         |                                       |
         v                                       v
   securetransfer.db                      securetransfer.db
   (send/resume state)                    (receive, audit)
```

---

## Performance benchmarks (reference)

| Scenario              | Approx. throughput | Notes                    |
|-----------------------|--------------------|--------------------------|
| LAN, 100 MB file      | ~80–120 MB/s       | Zstd level 3, no throttle|
| LAN, 1 GB file        | ~70–100 MB/s       | Chunked, resume-capable  |
| WAN, 10 MB file       | ~5–15 MB/s         | Depends on RTT and loss  |
| Server (rate-limited) | ≤10 MB/s per conn  | Token bucket 10 MB/s     |

*Actual numbers depend on CPU, disk, and network. Run your own benchmarks with `send`/`receive` and measure elapsed time vs. file size.*

---

## Configuration

Settings are loaded from environment variables with sane defaults. Call `config.validate()` on startup (the `receive` command does this).

| Variable                         | Default     | Description                          |
|----------------------------------|------------|--------------------------------------|
| `ST_HOST` / `ST_PORT`           | 0.0.0.0 / 9000 | Bind address and port (1024–65535) |
| `ST_MAX_TRANSFER_SIZE`          | 10 GB      | Max total transfer size              |
| `ST_MAX_PAYLOAD_SIZE`          | 64 MB      | Max single packet payload            |
| `ST_MAX_CONCURRENT_PER_IP`     | 5          | Max concurrent connections per IP     |
| `ST_RATE_LIMIT_BYTES_PER_SEC`  | 10 MB/s    | Token bucket rate per connection     |
| `ST_FAILED_HANDSHAKE_BAN_THRESHOLD` | 3     | Failed handshakes before ban         |
| `ST_FAILED_HANDSHAKE_BAN_WINDOW_SEC` | 60   | Window in seconds for ban            |
| `ST_LOG_PATH` / `LOG_LEVEL`     | logs/... / INFO | Log file and level               |
| `ST_LOG_ROTATION` / `ST_LOG_RETENTION` | 10 MB / 7 days | Log rotation and retention   |
| `DB_PATH`                       | securetransfer.db | SQLite database path             |

---

## Development

Run tests:

```bash
pytest
```

Run with verbose output:

```bash
LOG_LEVEL=DEBUG securetransfer receive --port 9000
```
