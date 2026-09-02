"""A minimal protobuf wire-format reader.

Android OTA payloads describe themselves with a protobuf message.  Rather than
take a dependency on the generated ``update_metadata_pb2`` (or on protobuf
itself) for the handful of fields we need, we walk the wire format directly.

This reads the wire format only -- it knows nothing about schemas. Callers pull
out the field numbers they care about and ignore the rest, which is exactly how
protobuf is meant to degrade when it meets a message it only partly understands.
"""

from __future__ import annotations

from dataclasses import dataclass, field

WIRE_VARINT = 0
WIRE_64BIT = 1
WIRE_LENGTH = 2
WIRE_32BIT = 5


class ProtobufError(ValueError):
    pass


def read_varint(data: bytes, pos: int) -> tuple[int, int]:
    result = shift = 0
    while True:
        if pos >= len(data):
            raise ProtobufError("truncated varint")
        byte = data[pos]
        pos += 1
        result |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return result, pos
        shift += 7
        if shift > 63:
            raise ProtobufError("varint is too long")


@dataclass
class Message:
    """Decoded fields, keyed by field number. Repeated fields keep every value."""

    fields: dict[int, list] = field(default_factory=dict)

    def add(self, number: int, value) -> None:
        self.fields.setdefault(number, []).append(value)

    def get(self, number: int, default=None):
        values = self.fields.get(number)
        return values[0] if values else default

    def get_all(self, number: int) -> list:
        return self.fields.get(number, [])

    def submessage(self, number: int) -> "Message | None":
        raw = self.get(number)
        return parse(raw) if isinstance(raw, bytes) else None

    def submessages(self, number: int) -> list["Message"]:
        return [parse(v) for v in self.get_all(number) if isinstance(v, bytes)]

    def string(self, number: int, default: str = "") -> str:
        raw = self.get(number)
        if isinstance(raw, bytes):
            return raw.decode("utf-8", "replace")
        return default

    def integer(self, number: int, default: int = 0) -> int:
        raw = self.get(number)
        return raw if isinstance(raw, int) else default


def parse(data: bytes) -> Message:
    """Decode a protobuf message body into a :class:`Message`."""
    msg = Message()
    pos = 0
    while pos < len(data):
        key, pos = read_varint(data, pos)
        number, wire_type = key >> 3, key & 0x07
        if number == 0:
            raise ProtobufError("field number 0 is not valid")
        if wire_type == WIRE_VARINT:
            value, pos = read_varint(data, pos)
            msg.add(number, value)
        elif wire_type == WIRE_64BIT:
            if pos + 8 > len(data):
                raise ProtobufError("truncated 64-bit field")
            msg.add(number, int.from_bytes(data[pos : pos + 8], "little"))
            pos += 8
        elif wire_type == WIRE_LENGTH:
            length, pos = read_varint(data, pos)
            if pos + length > len(data):
                raise ProtobufError("truncated length-delimited field")
            msg.add(number, data[pos : pos + length])
            pos += length
        elif wire_type == WIRE_32BIT:
            if pos + 4 > len(data):
                raise ProtobufError("truncated 32-bit field")
            msg.add(number, int.from_bytes(data[pos : pos + 4], "little"))
            pos += 4
        else:
            raise ProtobufError(f"unsupported wire type {wire_type}")
    return msg
