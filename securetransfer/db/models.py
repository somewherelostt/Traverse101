"""SQLAlchemy ORM models and repository for transfer tracking."""

from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import DateTime, ForeignKey, Index, Integer, String, func
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship

from loguru import logger

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession


class Base(DeclarativeBase):
    """Declarative base for all models."""

    pass


class Transfer(Base):
    """Records every send/receive attempt."""

    __tablename__ = "transfers"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    transfer_id: Mapped[str] = mapped_column(
        String(36), unique=True, index=True, nullable=False
    )
    direction: Mapped[str] = mapped_column(String(16), nullable=False)  # 'send' | 'receive'
    filename: Mapped[str] = mapped_column(String(1024), nullable=False)
    file_size: Mapped[int] = mapped_column(Integer, nullable=False)
    total_pieces: Mapped[int] = mapped_column(Integer, nullable=False)
    completed_pieces: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    status: Mapped[str] = mapped_column(
        String(32), nullable=False
    )  # in_progress, completed, failed, paused
    remote_host: Mapped[str] = mapped_column(String(512), nullable=False)
    file_hash: Mapped[str] = mapped_column(String(64), nullable=False)  # SHA-256 hex
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False
    )

    piece_statuses: Mapped[list[PieceStatus]] = relationship(
        "PieceStatus",
        back_populates="transfer",
        cascade="all, delete-orphan",
    )


class PieceStatus(Base):
    """Tracks which pieces have been confirmed received/sent."""

    __tablename__ = "piece_statuses"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    transfer_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("transfers.transfer_id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    piece_index: Mapped[int] = mapped_column(Integer, nullable=False)
    status: Mapped[str] = mapped_column(
        String(32), nullable=False
    )  # pending, transferred, verified, failed
    attempts: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    verified_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    transfer: Mapped[Transfer] = relationship("Transfer", back_populates="piece_statuses")

    __table_args__ = (
        Index("ix_piece_statuses_transfer_piece", "transfer_id", "piece_index", unique=True),
    )


class TransferRepository:
    """Async repository for Transfer and PieceStatus operations."""

    def __init__(self, session: AsyncSession) -> None:
        """Inject the async session to use for all operations."""
        self._session = session

    async def create_transfer(
        self,
        transfer_id: str,
        direction: str,
        filename: str,
        file_size: int,
        total_pieces: int,
        remote_host: str,
        file_hash: str,
    ) -> Transfer:
        """Create a new transfer record and piece status rows for each piece.

        Args:
            transfer_id: Unique transfer UUID.
            direction: 'send' or 'receive'.
            filename: Original filename.
            file_size: Total file size in bytes.
            total_pieces: Number of pieces.
            remote_host: Remote host identifier.
            file_hash: SHA-256 of full file (hex).

        Returns:
            The created Transfer instance.
        """
        transfer = Transfer(
            transfer_id=transfer_id,
            direction=direction,
            filename=filename,
            file_size=file_size,
            total_pieces=total_pieces,
            completed_pieces=0,
            status="in_progress",
            remote_host=remote_host,
            file_hash=file_hash,
        )
        self._session.add(transfer)
        await self._session.flush()
        for i in range(total_pieces):
            self._session.add(
                PieceStatus(
                    transfer_id=transfer_id,
                    piece_index=i,
                    status="pending",
                    attempts=0,
                )
            )
        await self._session.flush()
        logger.debug(
            "create_transfer: {} {} {} ({} pieces)",
            transfer_id,
            direction,
            filename,
            total_pieces,
        )
        return transfer

    async def get_transfer(self, transfer_id: str) -> Transfer | None:
        """Return the transfer with the given transfer_id, or None."""
        from sqlalchemy import select

        result = await self._session.execute(
            select(Transfer).where(Transfer.transfer_id == transfer_id)
        )
        return result.scalar_one_or_none()

    async def list_transfers(
        self,
        direction: str | None = None,
        filename: str | None = None,
        limit: int = 10,
    ) -> list[Transfer]:
        """Return recent transfers, optionally filtered by direction and/or filename."""
        from sqlalchemy import select

        q = select(Transfer).order_by(Transfer.created_at.desc()).limit(limit)
        if direction is not None:
            q = q.where(Transfer.direction == direction)
        if filename is not None:
            q = q.where(Transfer.filename == filename)
        result = await self._session.execute(q)
        return list(result.scalars().all())

    async def update_transfer_status(self, transfer_id: str, status: str) -> None:
        """Update the status of a transfer.

        Args:
            transfer_id: Transfer UUID.
            status: New status (e.g. 'in_progress', 'completed', 'failed', 'paused').
        """
        from sqlalchemy import update

        await self._session.execute(
            update(Transfer).where(Transfer.transfer_id == transfer_id).values(status=status)
        )
        logger.debug("update_transfer_status: {} -> {}", transfer_id, status)

    async def update_piece_status(
        self, transfer_id: str, piece_index: int, status: str
    ) -> None:
        """Update the status of a single piece.

        Args:
            transfer_id: Transfer UUID.
            piece_index: Piece index.
            status: New status (e.g. 'pending', 'transferred', 'verified', 'failed').
        """
        from sqlalchemy import update

        await self._session.execute(
            update(PieceStatus)
            .where(
                PieceStatus.transfer_id == transfer_id,
                PieceStatus.piece_index == piece_index,
            )
            .values(status=status)
        )
        logger.debug(
            "update_piece_status: {} piece {} -> {}",
            transfer_id,
            piece_index,
            status,
        )

    async def get_missing_pieces(self, transfer_id: str) -> list[int]:
        """Return piece indices where status is not 'verified'.

        Args:
            transfer_id: Transfer UUID.

        Returns:
            Sorted list of piece indices that are not verified.
        """
        from sqlalchemy import select

        result = await self._session.execute(
            select(PieceStatus.piece_index).where(
                PieceStatus.transfer_id == transfer_id,
                PieceStatus.status != "verified",
            ).order_by(PieceStatus.piece_index)
        )
        return list(result.scalars().all())

    async def get_all_transfers(self) -> list[Transfer]:
        """Return all transfer records, ordered by created_at descending."""
        from sqlalchemy import select

        result = await self._session.execute(
            select(Transfer).order_by(Transfer.created_at.desc())
        )
        return list(result.scalars().all())

    async def mark_piece_verified(self, transfer_id: str, piece_index: int) -> None:
        """Set piece status to 'verified' and set verified_at to now.

        Also increments the transfer's completed_pieces count.
        """
        from datetime import datetime, timezone
        from sqlalchemy import update

        now = datetime.now(timezone.utc)
        await self._session.execute(
            update(PieceStatus)
            .where(
                PieceStatus.transfer_id == transfer_id,
                PieceStatus.piece_index == piece_index,
            )
            .values(status="verified", verified_at=now)
        )
        # Increment completed_pieces on the transfer
        await self._session.execute(
            update(Transfer)
            .where(Transfer.transfer_id == transfer_id)
            .values(completed_pieces=Transfer.completed_pieces + 1)
        )
        logger.debug("mark_piece_verified: {} piece {}", transfer_id, piece_index)

    async def increment_piece_attempts(self, transfer_id: str, piece_index: int) -> None:
        """Increment the attempts count for a piece."""
        from sqlalchemy import update

        await self._session.execute(
            update(PieceStatus)
            .where(
                PieceStatus.transfer_id == transfer_id,
                PieceStatus.piece_index == piece_index,
            )
            .values(attempts=PieceStatus.attempts + 1)
        )
        logger.debug("increment_piece_attempts: {} piece {}", transfer_id, piece_index)

    async def commit(self) -> None:
        """Commit the current transaction (e.g. to release SQLite lock for another connection)."""
        await self._session.commit()
