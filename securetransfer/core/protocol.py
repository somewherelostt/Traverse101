"""Binary packet framing layer for secure file transfer protocol."""

from __future__ import annotations

import asyncio
import base64
import json
import struct
from enum import IntEnum
from typing import Any

# --- Constants ----------------------------------------------------------------

MAGIC = b"SCDT"  # Secure Compressed Data Transfer
VERSION = 1

# Header: 4 + 1 + 1 + 2 + 4 + 8 = 20 bytes
HEADER_FORMAT = "<4sBBHIQ"
HEADER_SIZE = struct.calcsize(HEADER_FORMAT)


# --- Packet type -------------------------------------------------------------


class PacketType(IntEnum):
    """Packet type identifiers."""

    HANDSHAKE_INIT = 0x01
    HANDSHAKE_RESP = 0x02
    MANIFEST = 0x03
    PIECE = 0x04
    PIECE_ACK = 0x05
    PIECE_NACK = 0x06  # request retransmit
    TRANSFER_COMPLETE = 0x07
    ERROR = 0x08
    HEARTBEAT = 0x09


# --- Exceptions --------------------------------------------------------------


class InvalidMagicError(Exception):
    """Raised when packet magic bytes do not match MAGIC."""

    pass


class VersionMismatchError(Exception):
    """Raised when packet version does not match VERSION."""

    pass


class PacketParseError(Exception):
    """Raised when packet binary data cannot be parsed (truncated, invalid)."""

    pass


# --- Packet -------------------------------------------------------------------


class Packet:
    """Binary packet with fixed 20-byte header and variable payload."""

    __slots__ = ("_packet_type", "_payload", "_transfer_id", "_flags")

    def __init__(
        self,
        packet_type: PacketType,
        payload: bytes,
        transfer_id: int = 0,
        flags: int = 0,
    ) -> None:
        """Build a packet.

        Args:
            packet_type: PacketType value.
            payload: Raw payload bytes.
            transfer_id: 64-bit transfer identifier (default 0).
            flags: 16-bit flags (default 0).
        """
        self._packet_type = PacketType(packet_type)
        self._payload = bytes(payload)
        self._transfer_id = int(transfer_id) & 0xFFFF_FFFF_FFFF_FFFF
        self._flags = int(flags) & 0xFFFF

    @property
    def packet_type(self) -> PacketType:
        """Packet type."""
        return self._packet_type

    @property
    def payload(self) -> bytes:
        """Payload bytes."""
        return self._payload

    @property
    def payload_length(self) -> int:
        """Length of payload in bytes."""
        return len(self._payload)

    @property
    def transfer_id(self) -> int:
        """Transfer ID from header."""
        return self._transfer_id

    @property
    def flags(self) -> int:
        """Flags from header."""
        return self._flags

    def to_bytes(self) -> bytes:
        """Serialize to header + payload using struct.pack.

        Returns:
            Exactly HEADER_SIZE + len(payload) bytes.
        """
        header = struct.pack(
            HEADER_FORMAT,
            MAGIC,
            VERSION,
            int(self._packet_type),
            self._flags,
            len(self._payload),
            self._transfer_id,
        )
        return header + self._payload

    @classmethod
    def from_bytes(cls, data: bytes) -> Packet:
        """Deserialize from bytes; validate magic and version.

        Args:
            data: Full packet (header + payload).

        Returns:
            Packet instance.

        Raises:
            InvalidMagicError: If magic bytes are wrong.
            VersionMismatchError: If version is not VERSION.
            PacketParseError: If data is truncated or invalid.
        """
        if len(data) < HEADER_SIZE:
            raise PacketParseError(
                f"Packet too short: need at least {HEADER_SIZE} bytes, got {len(data)}"
            )
        magic, version, ptype, flags, payload_len, transfer_id = struct.unpack(
            HEADER_FORMAT, data[:HEADER_SIZE]
        )
        if magic != MAGIC:
            raise InvalidMagicError(f"Invalid magic: expected {MAGIC!r}, got {magic!r}")
        if version != VERSION:
            raise VersionMismatchError(
                f"Version mismatch: expected {VERSION}, got {version}"
            )
        if len(data) < HEADER_SIZE + payload_len:
            raise PacketParseError(
                f"Payload truncated: need {payload_len} bytes, "
                f"got {len(data) - HEADER_SIZE}"
            )
        payload = data[HEADER_SIZE : HEADER_SIZE + payload_len]
        return cls(
            packet_type=PacketType(ptype),
            payload=payload,
            transfer_id=transfer_id,
            flags=flags,
        )


# --- PacketBuilder ------------------------------------------------------------


class PacketBuilder:
    """Build specific packet types with JSON-encoded structured payloads."""

    @staticmethod
    def _json_payload(obj: dict[str, Any]) -> bytes:
        """Encode dict as JSON bytes."""
        return json.dumps(obj, separators=(",", ":")).encode("utf-8")

    @classmethod
    def build_handshake_init(cls, public_key: bytes, salt: bytes) -> Packet:
        """Build HANDSHAKE_INIT packet with public_key and salt (base64 in JSON)."""
        payload = cls._json_payload({
            "public_key": base64.b64encode(public_key).decode("ascii"),
            "salt": base64.b64encode(salt).decode("ascii"),
        })
        return Packet(PacketType.HANDSHAKE_INIT, payload)

    @classmethod
    def build_handshake_resp(
        cls, public_key: bytes, session_id: int
    ) -> Packet:
        """Build HANDSHAKE_RESP packet with public_key and session_id."""
        payload = cls._json_payload({
            "public_key": base64.b64encode(public_key).decode("ascii"),
            "session_id": session_id,
        })
        return Packet(PacketType.HANDSHAKE_RESP, payload)

    @classmethod
    def build_manifest(cls, manifest: dict[str, Any], transfer_id: int) -> Packet:
        """Build MANIFEST packet with transfer manifest dict."""
        payload = cls._json_payload(manifest)
        return Packet(PacketType.MANIFEST, payload, transfer_id=transfer_id)

    @classmethod
    def build_piece(
        cls, piece_index: int, data: bytes, transfer_id: int
    ) -> Packet:
        """Build PIECE packet with piece index and data (data as base64 in JSON)."""
        payload = cls._json_payload({
            "piece_index": piece_index,
            "data": base64.b64encode(data).decode("ascii"),
        })
        return Packet(PacketType.PIECE, payload, transfer_id=transfer_id)

    @classmethod
    def build_ack(cls, piece_index: int, transfer_id: int) -> Packet:
        """Build PIECE_ACK packet."""
        payload = cls._json_payload({"piece_index": piece_index})
        return Packet(PacketType.PIECE_ACK, payload, transfer_id=transfer_id)

    @classmethod
    def build_nack(cls, piece_index: int, transfer_id: int) -> Packet:
        """Build PIECE_NACK packet (request retransmit)."""
        payload = cls._json_payload({"piece_index": piece_index})
        return Packet(PacketType.PIECE_NACK, payload, transfer_id=transfer_id)

    @classmethod
    def build_error(cls, message: str, transfer_id: int) -> Packet:
        """Build ERROR packet with message."""
        payload = cls._json_payload({"message": message})
        return Packet(PacketType.ERROR, payload, transfer_id=transfer_id)


# --- FrameReader --------------------------------------------------------------


class FrameReader:
    """Read full packets from an asyncio stream, handling TCP fragmentation."""

    @staticmethod
    async def read_packet(reader: asyncio.StreamReader) -> Packet:
        """Read one packet: 20-byte header, then payload_length bytes.

        Args:
            reader: Asyncio stream reader (e.g. from asyncio.open_connection).

        Returns:
            Parsed Packet.

        Raises:
            InvalidMagicError: If magic in header is wrong.
            VersionMismatchError: If version in header is wrong.
            PacketParseError: If stream ends prematurely or parse fails.
        """
        header = await reader.readexactly(HEADER_SIZE)
        if len(header) != HEADER_SIZE:
            raise PacketParseError(
                f"Incomplete header: got {len(header)} bytes, need {HEADER_SIZE}"
            )
        magic, version, _ptype, _flags, payload_len, _transfer_id = struct.unpack(
            HEADER_FORMAT, header
        )
        if magic != MAGIC:
            raise InvalidMagicError(f"Invalid magic: expected {MAGIC!r}, got {magic!r}")
        if version != VERSION:
            raise VersionMismatchError(
                f"Version mismatch: expected {VERSION}, got {version}"
            )
        payload = await reader.readexactly(payload_len)
        return Packet.from_bytes(header + payload)
