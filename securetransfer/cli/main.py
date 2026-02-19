"""Click CLI for secure file transfer."""

from __future__ import annotations

import asyncio
import hashlib
import time
from pathlib import Path
from typing import Any

import click
from loguru import logger
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table

from securetransfer import config
from securetransfer.core.chunker import FileChunker
from securetransfer.db.models import TransferRepository
from securetransfer.db.session import get_session, init_db
from securetransfer.network.client import TransferClient
from securetransfer.network.server import TransferServer

console = Console()


def _human_size(n: int) -> str:
    """Format byte count as human-readable string."""
    for u in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024:
            return f"{n:.1f} {u}"
        n /= 1024
    return f"{n:.1f} PB"


@click.group()
def cli() -> None:
    """Secure file transfer: send, receive, status, resume, keygen."""
    pass


@cli.command("send")
@click.option("--host", required=True, type=str, help="Remote server host")
@click.option("--port", default=9000, type=int, help="Remote server port")
@click.option("--file", "file_path", required=True, type=click.Path(exists=True, path_type=Path), help="File to send")
@click.option("--compression-level", default=3, type=int, help="Zstd level 1-22")
def send_cmd(host: str, port: int, file_path: Path, compression_level: int) -> None:
    """Send a file to a remote server."""
    if not (1 <= compression_level <= 22):
        raise click.BadParameter("compression-level must be 1-22")
    if not file_path.is_file():
        raise click.BadParameter(f"Not a file: {file_path}")
    try:
        file_path.read_bytes()
    except Exception as e:
        raise click.BadParameter(f"File not readable: {e}")

    chunker = FileChunker(str(file_path))
    meta = chunker.get_file_metadata()
    console.print(f"[bold]File:[/] {meta['filename']}")
    console.print(f"[bold]Size:[/] {_human_size(meta['total_size'])}")
    console.print(f"[bold]Pieces:[/] {meta['total_pieces']} (est.)")
    console.print()

    async def _run() -> dict:
        await init_db()
        async with get_session() as session:
            repo = TransferRepository(session)
            client = TransferClient(host, port, repo)
            start = time.perf_counter()
            file_size = meta["total_size"]
            total_pieces = meta["total_pieces"]

            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=console,
            ) as progress:
                task = progress.add_task("Sending…", total=total_pieces)
                bytes_so_far = [0.0]
                t0 = [start]

                def on_progress(tid: str, completed: int, total: int) -> None:
                    progress.update(task, completed=completed)
                    bytes_so_far[0] = (completed / total) * file_size if total else 0
                    elapsed = time.perf_counter() - t0[0]
                    if elapsed > 0 and completed > 0:
                        speed_mbps = (bytes_so_far[0] / (1024 * 1024)) / elapsed
                        remain = file_size - bytes_so_far[0]
                        eta = remain / (bytes_so_far[0] / elapsed) if bytes_so_far[0] > 0 else 0
                        progress.console.print(
                            f"  [dim]~{speed_mbps:.2f} MB/s[/] [dim]ETA {eta:.0f}s[/]",
                            end="\r",
                        )

                result = await client.send_file(
                    str(file_path),
                    compression_level=compression_level,
                    progress_callback=on_progress,
                )
            result["_elapsed"] = time.perf_counter() - start
            result["_file_size"] = file_size
            return result

    try:
        result = asyncio.run(_run())
    except Exception as e:
        logger.exception("send failed")
        console.print(f"[red]Error:[/] {e}")
        console.print("[yellow]To retry from where you left off, run:[/]")
        console.print("  [bold]securetransfer resume --transfer-id <ID> --host <host> --port <port> --file <path>[/]")
        raise SystemExit(1)

    if result.get("status") == "failed":
        console.print(f"[red]Transfer failed:[/] {result.get('error', 'unknown')}")
        console.print("[yellow]Resume with:[/]")
        console.print(f"  [bold]securetransfer resume --transfer-id {result.get('transfer_id', '')} --host {host} --port {port} --file {file_path}[/]")
        raise SystemExit(1)

    elapsed = result.get("_elapsed", 0)
    file_size = result.get("_file_size", 0)
    speed = (file_size / (1024 * 1024)) / elapsed if elapsed > 0 else 0
    console.print("[green]Transfer complete.[/]")
    console.print(f"  [bold]Transfer ID:[/] {result['transfer_id']}")
    console.print(f"  [bold]Time:[/] {elapsed:.2f} s")
    console.print(f"  [bold]Size:[/] {_human_size(file_size)}")
    console.print(f"  [bold]Speed:[/] {speed:.2f} MB/s")


@cli.command("receive")
@click.option("--host", default="0.0.0.0", type=str, help="Host to bind")
@click.option("--port", default=9000, type=int, help="Port to bind")
@click.option("--output-dir", default=".", type=click.Path(path_type=Path), help="Where to save received files")
def receive_cmd(host: str, port: int, output_dir: Path) -> None:
    """Start server and receive files."""
    try:
        config.validate()
    except config.ConfigError as e:
        raise click.BadParameter(str(e)) from e
    config.configure_logging()
    output_dir = output_dir.resolve()
    output_dir.mkdir(parents=True, exist_ok=True)

    async def _run() -> None:
        await init_db()
        async with get_session() as session:
            repo = TransferRepository(session)
            progress_bars: dict[str, Any] = {}
            completed_tasks: dict[str, Any] = {}

            def on_progress(tid: str, filename: str, completed: int, total: int) -> None:
                key = tid
                if key not in progress_bars:
                    progress_bars[key] = Progress(
                        SpinnerColumn(),
                        TextColumn("[progress.description]{task.description}"),
                        console=console,
                    )
                    progress_bars[key].start()
                    completed_tasks[key] = progress_bars[key].add_task(f"[cyan]{filename}[/]", total=total)
                progress_bars[key].update(completed_tasks[key], completed=completed)

            def on_complete(tid: str, filename: str, save_path: str | None, verified: bool) -> None:
                key = tid
                if key in progress_bars:
                    progress_bars[key].stop()
                    del progress_bars[key]
                    del completed_tasks[key]
                if save_path:
                    console.print(f"[green]Saved:[/] {save_path}")
                    console.print(f"  [bold]Hash verified:[/] {'[green]OK[/]' if verified else '[red]FAIL[/]'}")

            server = TransferServer(
                host,
                port,
                repo,
                output_dir=str(output_dir),
                progress_callback=on_progress,
                on_complete_callback=on_complete,
            )
            await server.start()
            console.print(f"[bold]Listening on {host}:{port}[/] (output: {output_dir})")
            try:
                while True:
                    await asyncio.sleep(3600)
            except asyncio.CancelledError:
                pass
            finally:
                await server.stop()

    try:
        asyncio.run(_run())
    except KeyboardInterrupt:
        console.print("\n[yellow]Stopped.[/]")


@cli.command("status")
@click.option("--transfer-id", type=str, help="Show specific transfer")
@click.option("--all", "show_all", is_flag=True, help="Show all transfers")
def status_cmd(transfer_id: str | None, show_all: bool) -> None:
    """Show transfer status from the database."""
    if not show_all and not transfer_id:
        raise click.UsageError("Use --transfer-id <id> or --all")

    async def _run() -> None:
        await init_db()
        async with get_session() as session:
            repo = TransferRepository(session)
            if transfer_id:
                t = await repo.get_transfer(transfer_id)
                rows = [t] if t else []
            else:
                rows = await repo.get_all_transfers()

        table = Table(show_header=True, header_style="bold")
        table.add_column("transfer_id", style="dim")
        table.add_column("filename")
        table.add_column("direction")
        table.add_column("status")
        table.add_column("progress")
        table.add_column("created_at")
        for t in rows:
            pct = (100 * t.completed_pieces / t.total_pieces) if t.total_pieces else 0
            table.add_row(
                t.transfer_id[:8] + "…" if len(t.transfer_id) > 8 else t.transfer_id,
                t.filename[:30] + "…" if len(t.filename) > 30 else t.filename,
                t.direction,
                t.status,
                f"{pct:.0f}%",
                str(t.created_at)[:19] if t.created_at else "",
            )
        console.print(table)

    asyncio.run(_run())


@cli.command("resume")
@click.option("--transfer-id", required=True, type=str, help="Transfer to resume")
@click.option("--host", required=True, type=str, help="Remote server host")
@click.option("--port", default=9000, type=int, help="Remote server port")
@click.option("--file", "file_path", required=True, type=click.Path(exists=True, path_type=Path), help="Same file as original send")
def resume_cmd(transfer_id: str, host: str, port: int, file_path: Path) -> None:
    """Resume a failed or paused transfer."""
    async def _run() -> dict:
        await init_db()
        async with get_session() as session:
            repo = TransferRepository(session)
            client = TransferClient(host, port, repo)
            return await client.resume_transfer(transfer_id, str(file_path))

    try:
        result = asyncio.run(_run())
        console.print("[green]Resume complete.[/]")
        console.print(f"  [bold]Transfer ID:[/] {result.get('transfer_id')}")
        console.print(f"  [bold]Filename:[/] {result.get('filename')}")
        if result.get("missing_sent"):
            console.print(f"  [bold]Pieces sent:[/] {result['missing_sent']}")
    except ValueError as e:
        console.print(f"[red]{e}[/]")
        raise SystemExit(1)
    except Exception as e:
        logger.exception("resume failed")
        console.print(f"[red]Error:[/] {e}")
        raise SystemExit(1)


@cli.command("keygen")
@click.option("--output", default="./keys", type=click.Path(path_type=Path), help="Directory for key files")
@click.option("--password", type=str, help="Password for private key (prompted if omitted)")
def keygen_cmd(output: Path, password: str | None) -> None:
    """Generate X25519 keypair and save to disk."""
    from securetransfer.core.encryption import KeyManager

    output = output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    if password is None:
        password = click.prompt("Password for private key", hide_input=True, confirmation_prompt=True)

    km = KeyManager()
    private_bytes, public_bytes = km.generate_keypair()
    priv_path = output / "private.pem"
    pub_path = output / "public.bin"
    km.save_keypair(private_bytes, str(priv_path), password)
    pub_path.write_bytes(public_bytes)
    fingerprint = hashlib.sha256(public_bytes).hexdigest()
    console.print(f"[green]Keys written to[/] {output}")
    console.print(f"  Private: {priv_path}")
    console.print(f"  Public:  {pub_path}")
    console.print(f"[bold]Public key fingerprint (SHA-256):[/] {fingerprint}")


if __name__ == "__main__":
    cli()
