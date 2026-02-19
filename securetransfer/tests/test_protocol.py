"""Tests for protocol packet framing."""

import asyncio
import struct

import pytest

from securetransfer.core.protocol import (
    HEADER_FORMAT,
    HEADER_SIZE,
    MAGIC,
    VERSION,
    FrameReader,
    InvalidMagicError,
    Packet,
    PacketBuilder,
    PacketParseError,
    PacketType,
    VersionMismatchError,
)


def test_packet_serialize_deserialize() -> None:
    """Packet to_bytes then from_bytes roundtrips correctly."""
    payload = b"hello world"
    p = Packet(PacketType.HEARTBEAT, payload, transfer_id=12345, flags=1)
    raw = p.to_bytes()
    assert len(raw) == 20 + len(payload)
    p2 = Packet.from_bytes(raw)
    assert p2.packet_type == PacketType.HEARTBEAT
    assert p2.payload == payload
    assert p2.payload_length == len(payload)
    assert p2.transfer_id == 12345
    assert p2.flags == 1


def test_invalid_magic_raises_error() -> None:
    """from_bytes raises InvalidMagicError when magic is wrong."""
    p = Packet(PacketType.HEARTBEAT, b"")
    raw = p.to_bytes()
    bad = b"XXXX" + raw[4:]  # wrong magic
    with pytest.raises(InvalidMagicError):
        Packet.from_bytes(bad)
    # Also test truncated packet
    with pytest.raises(PacketParseError):
        Packet.from_bytes(raw[:10])
    # Payload length says 100 but we only have 20 bytes
    header_bad = struct.pack("<4sBBHIQ", MAGIC, VERSION, 0x09, 0, 100, 0)
    with pytest.raises(PacketParseError):
        Packet.from_bytes(header_bad)


def test_version_mismatch_raises() -> None:
    """from_bytes raises VersionMismatchError when version is wrong."""
    p = Packet(PacketType.HEARTBEAT, b"")
    raw = p.to_bytes()
    bad_version = raw[:4] + bytes([99]) + raw[5:]  # version 99
    with pytest.raises(VersionMismatchError):
        Packet.from_bytes(bad_version)


def test_all_packet_types_build_correctly() -> None:
    """PacketBuilder builds each packet type and roundtrip parses."""
    # Handshake init
    pk = PacketBuilder.build_handshake_init(public_key=b"x" * 32, salt=b"y" * 16)
    assert pk.packet_type == PacketType.HANDSHAKE_INIT
    p2 = Packet.from_bytes(pk.to_bytes())
    assert p2.packet_type == PacketType.HANDSHAKE_INIT
    assert p2.payload_length > 0

    # Handshake resp
    pk = PacketBuilder.build_handshake_resp(public_key=b"a" * 32, session_id=999)
    assert pk.packet_type == PacketType.HANDSHAKE_RESP
    p2 = Packet.from_bytes(pk.to_bytes())
    assert p2.packet_type == PacketType.HANDSHAKE_RESP

    # Manifest
    pk = PacketBuilder.build_manifest(
        {"filename": "f.bin", "total_pieces": 10}, transfer_id=1
    )
    assert pk.packet_type == PacketType.MANIFEST
    assert pk.transfer_id == 1
    p2 = Packet.from_bytes(pk.to_bytes())
    assert p2.transfer_id == 1

    # Piece
    pk = PacketBuilder.build_piece(piece_index=3, data=b"chunk data", transfer_id=2)
    assert pk.packet_type == PacketType.PIECE
    assert pk.transfer_id == 2
    p2 = Packet.from_bytes(pk.to_bytes())
    assert p2.payload_length > 0

    # Ack
    pk = PacketBuilder.build_ack(piece_index=5, transfer_id=2)
    assert pk.packet_type == PacketType.PIECE_ACK
    p2 = Packet.from_bytes(pk.to_bytes())
    assert p2.packet_type == PacketType.PIECE_ACK

    # Nack
    pk = PacketBuilder.build_nack(piece_index=7, transfer_id=2)
    assert pk.packet_type == PacketType.PIECE_NACK
    p2 = Packet.from_bytes(pk.to_bytes())
    assert p2.packet_type == PacketType.PIECE_NACK

    # Error
    pk = PacketBuilder.build_error(message="something failed", transfer_id=2)
    assert pk.packet_type == PacketType.ERROR
    p2 = Packet.from_bytes(pk.to_bytes())
    assert p2.packet_type == PacketType.ERROR


class _MockStreamReader:
    """Minimal reader that returns bytes from a buffer; supports readexactly."""

    def __init__(self, data: bytes) -> None:
        self._data = data
        self._pos = 0

    async def readexactly(self, n: int) -> bytes:
        if self._pos + n > len(self._data):
            raise asyncio.IncompleteReadError(
                self._data[self._pos :], n
            )
        result = self._data[self._pos : self._pos + n]
        self._pos += n
        return result


def test_frame_reader_with_simulated_stream() -> None:
    """FrameReader.read_packet correctly reads a full packet from a simulated stream."""
    async def _run() -> None:
        p = Packet(PacketType.MANIFEST, b'{"key": "value"}', transfer_id=42)
        raw = p.to_bytes()
        reader = _MockStreamReader(raw)
        packet = await FrameReader.read_packet(reader)
        assert packet.packet_type == PacketType.MANIFEST
        assert packet.payload == b'{"key": "value"}'
        assert packet.transfer_id == 42

        # Two packets in a row
        p1 = Packet(PacketType.HEARTBEAT, b"ping")
        p2 = Packet(PacketType.HEARTBEAT, b"pong")
        reader2 = _MockStreamReader(p1.to_bytes() + p2.to_bytes())
        r1 = await FrameReader.read_packet(reader2)
        r2 = await FrameReader.read_packet(reader2)
        assert r1.payload == b"ping"
        assert r2.payload == b"pong"

    asyncio.run(_run())


def test_frame_reader_rejects_oversized_payload() -> None:
    """read_packet with max_payload_size rejects payload_len > max (validate packet fields)."""
    async def _run() -> None:
        # Header only: payload_len = 1_000_000, no payload bytes provided
        header = struct.pack(
            HEADER_FORMAT,
            MAGIC,
            VERSION,
            int(PacketType.MANIFEST),
            0,
            1_000_000,  # payload_len
            0,
        )
        reader = _MockStreamReader(header)
        with pytest.raises(PacketParseError, match="exceeds maximum"):
            await FrameReader.read_packet(reader, max_payload_size=64 * 1024)

    asyncio.run(_run())
