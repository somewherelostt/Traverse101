#!/usr/bin/env python3
"""Benchmark script: transfer 100MB file 5x, report speed, compression ratio, encryption overhead.

Compares: with compression vs without, with encryption vs without.
"""

from __future__ import annotations

import asyncio
import os
import tempfile
import time
from pathlib import Path

# Ensure we can import securetransfer
import sys
# Ensure package root is on path when run as script (e.g. python tests/benchmark.py)
_project_root = Path(__file__).resolve().parent.parent.parent
if str(_project_root) not in sys.path:
    sys.path.insert(0, str(_project_root))

from securetransfer.core.compression import Compressor
from securetransfer.core.encryption import AESCipher, KeyManager

SIZE_100MB = 100 * 1024 * 1024
RUNS = 5


def _human_size(n: int) -> str:
    if n < 1024:
        return f"{n} B"
    n /= 1024
    if n < 1024:
        return f"{n:.2f} KB"
    n /= 1024
    return f"{n:.2f} MB"


def create_test_file(path: Path, size: int, compressible: bool = False) -> None:
    if compressible:
        chunk = b"ABCDEFGH" * 128
        with open(path, "wb") as f:
            while f.tell() < size:
                f.write(chunk[: min(len(chunk), size - f.tell())])
    else:
        chunk_size = 1024 * 1024
        with open(path, "wb") as f:
            remaining = size
            while remaining > 0:
                f.write(os.urandom(min(chunk_size, remaining)))
                remaining -= chunk_size


def benchmark_compression(path: Path, runs: int = RUNS) -> tuple[float, float]:
    """Returns (avg_time_ms, compression_ratio)."""
    data = path.read_bytes()
    compressor = Compressor(level=3)
    times = []
    compressed_size = 0
    for _ in range(runs):
        t0 = time.perf_counter()
        out = compressor.compress(data)
        times.append((time.perf_counter() - t0) * 1000)
        compressed_size = len(out)
    ratio = len(data) / compressed_size if compressed_size else 0
    return sum(times) / len(times), ratio


def benchmark_encryption(path: Path, runs: int = RUNS) -> tuple[float, float]:
    """Returns (avg_time_ms, overhead_ms)."""
    data = path.read_bytes()
    km = KeyManager()
    _, pub = km.generate_keypair()
    salt = km.generate_salt()
    shared = os.urandom(32)
    key = km.derive_symmetric_key(shared, salt)
    cipher = AESCipher(key)
    times = []
    for _ in range(runs):
        t0 = time.perf_counter()
        cipher.encrypt(data)
        times.append((time.perf_counter() - t0) * 1000)
    return sum(times) / len(times), sum(times) / len(times)


def benchmark_transfer(path: Path, runs: int = RUNS) -> tuple[float, float]:
    """Run full transfer 5 times; returns (avg_speed_MB_s, avg_time_s). Server started in-process."""
    try:
        from securetransfer.db.session import get_session, init_db
        from securetransfer.network.client import TransferClient
        from securetransfer.network.server import TransferServer
        from securetransfer.db.models import TransferRepository
    except ImportError:
        print("Transfer benchmark skipped (import error).")
        return 0.0, 0.0

    os.environ["DB_PATH"] = tempfile.mktemp(suffix=".db", prefix="bench_")

    async def _one_run() -> float:
        await init_db()
        async with get_session() as s1:
            async with get_session() as s2:
                server_repo = TransferRepository(s1)
                client_repo = TransferRepository(s2)
                server = TransferServer("127.0.0.1", 0, server_repo)
                await server.start()
                port = server._server.sockets[0].getsockname()[1]
                try:
                    client = TransferClient("127.0.0.1", port, client_repo)
                    t0 = time.perf_counter()
                    await client.send_file(str(path))
                    return time.perf_counter() - t0
                finally:
                    await server.stop()

    times = []
    for i in range(runs):
        try:
            elapsed = asyncio.run(_one_run())
            times.append(elapsed)
        except Exception as e:
            print(f"  Run {i+1} failed: {e}")
    if not times:
        return 0.0, 0.0
    avg_time = sum(times) / len(times)
    size_mb = path.stat().st_size / (1024 * 1024)
    speed = size_mb / avg_time if avg_time > 0 else 0
    return speed, avg_time


def main() -> None:
    print("=== SecureTransfer benchmark (100 MB, 5 runs each) ===\n")
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        path = tmp / "bench_100mb.bin"
        path_compressible = tmp / "bench_100mb_compressible.bin"
        create_test_file(path, SIZE_100MB, compressible=False)
        create_test_file(path_compressible, SIZE_100MB, compressible=True)

        print("1. Compression only (random data)")
        avg_ms, ratio = benchmark_compression(path)
        print(f"   Avg time: {avg_ms:.2f} ms")
        print(f"   Compression ratio: {ratio:.2f}x\n")

        print("2. Compression only (compressible data)")
        avg_ms_c, ratio_c = benchmark_compression(path_compressible)
        print(f"   Avg time: {avg_ms_c:.2f} ms")
        print(f"   Compression ratio: {ratio_c:.2f}x\n")

        print("3. Encryption only (100 MB)")
        avg_enc_ms, overhead_ms = benchmark_encryption(path)
        print(f"   Avg encryption time: {avg_enc_ms:.2f} ms")
        print(f"   Avg encryption overhead: {overhead_ms:.2f} ms\n")

        print("4. Full transfer (requires server; run receive in another terminal)")
        speed, avg_time = benchmark_transfer(path)
        if speed > 0:
            print(f"   Avg speed: {speed:.2f} MB/s")
            print(f"   Avg time: {avg_time:.2f} s")
        else:
            print("   Skipped (no server or import error).")

        print("\n--- Summary ---")
        print(f"   With compression (random): {ratio:.2f}x ratio, {avg_ms:.0f} ms")
        print(f"   With compression (compressible): {ratio_c:.2f}x ratio")
        print(f"   Encryption overhead: {overhead_ms:.0f} ms per 100 MB")


if __name__ == "__main__":
    main()
