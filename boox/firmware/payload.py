"""Android A/B OTA payload (``payload.bin``) reader.

A full Onyx firmware package contains one of these, and it is where the stock
``boot``, ``init_boot`` and ``vbmeta`` images come from -- the golden reference
the verifier checks candidate images against.

Only full-payload operations are supported (REPLACE, REPLACE_BZ, REPLACE_XZ and
ZERO), which is all a full OTA uses.  Incremental OTAs carry delta operations
that need the previous image to apply; those are rejected with an explanation
rather than half-applied, because a partially reconstructed golden image would
be worse than none at all.
"""

from __future__ import annotations

import bz2
import hashlib
import lzma
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO

from boox.errors import FirmwareError
from boox.firmware.protobuf import Message, ProtobufError, parse

MAGIC = b"CrAU"

# chromeos_update_engine.InstallOperation.Type
OP_REPLACE = 0
OP_REPLACE_BZ = 1
OP_ZERO = 6
OP_REPLACE_XZ = 8
FULL_OPS = {OP_REPLACE, OP_REPLACE_BZ, OP_ZERO, OP_REPLACE_XZ}
OP_NAMES = {
    0: "REPLACE", 1: "REPLACE_BZ", 2: "MOVE", 3: "BSDIFF", 4: "SOURCE_COPY",
    5: "SOURCE_BSDIFF", 6: "ZERO", 7: "DISCARD", 8: "REPLACE_XZ",
    9: "PUFFDIFF", 10: "BROTLI_BSDIFF", 11: "ZUCCHINI",
}

# Field numbers we care about, from update_metadata.proto.
_MANIFEST_BLOCK_SIZE = 3
_MANIFEST_PARTITIONS = 13
_PART_NAME = 1
_PART_OPERATIONS = 8
_PART_NEW_INFO = 9
_INFO_SIZE = 1
_INFO_HASH = 2
_OP_TYPE = 1
_OP_DATA_OFFSET = 2
_OP_DATA_LENGTH = 3
_OP_DST_EXTENTS = 6
_EXTENT_START = 1
_EXTENT_NUM = 2


@dataclass(frozen=True)
class Extent:
    start_block: int
    num_blocks: int


@dataclass(frozen=True)
class Operation:
    type: int
    data_offset: int
    data_length: int
    dst_extents: tuple[Extent, ...]

    @property
    def type_name(self) -> str:
        return OP_NAMES.get(self.type, f"UNKNOWN({self.type})")


@dataclass(frozen=True)
class PartitionEntry:
    name: str
    size: int
    sha256: str | None
    operations: tuple[Operation, ...]

    @property
    def is_full(self) -> bool:
        return all(op.type in FULL_OPS for op in self.operations)

    def unsupported_ops(self) -> set[str]:
        return {op.type_name for op in self.operations if op.type not in FULL_OPS}


class Payload:
    """Reads partition images out of an Android OTA ``payload.bin``."""

    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        self._fh: BinaryIO | None = None
        self.block_size = 4096
        self.partitions: dict[str, PartitionEntry] = {}
        self._data_offset = 0
        self._load()

    # ---- parsing --------------------------------------------------------------

    def _load(self) -> None:
        with open(self.path, "rb") as fh:
            header = fh.read(24)
            if len(header) < 24 or not header.startswith(MAGIC):
                raise FirmwareError(
                    f"{self.path.name} is not an Android OTA payload (missing 'CrAU' magic)",
                    remedy="Extract payload.bin from the decrypted update.zip first.",
                )
            version, manifest_size = struct.unpack(">QQ", header[4:20])
            if version < 2:
                raise FirmwareError(f"payload format version {version} is not supported")
            signature_size = struct.unpack(">I", header[20:24])[0]

            manifest_bytes = fh.read(manifest_size)
            if len(manifest_bytes) != manifest_size:
                raise FirmwareError("payload manifest is truncated")
            self._data_offset = 24 + manifest_size + signature_size

        try:
            manifest = parse(manifest_bytes)
        except ProtobufError as exc:
            raise FirmwareError(f"could not decode the payload manifest: {exc}") from exc

        self.block_size = manifest.integer(_MANIFEST_BLOCK_SIZE, 4096) or 4096
        for part in manifest.submessages(_MANIFEST_PARTITIONS):
            entry = self._partition_entry(part)
            self.partitions[entry.name] = entry
        if not self.partitions:
            raise FirmwareError("the payload manifest lists no partitions")

    def _partition_entry(self, part: Message) -> PartitionEntry:
        name = part.string(_PART_NAME)
        info = part.submessage(_PART_NEW_INFO)
        size = info.integer(_INFO_SIZE) if info else 0
        raw_hash = info.get(_INFO_HASH) if info else None
        digest = raw_hash.hex() if isinstance(raw_hash, bytes) else None

        operations = []
        for op in part.submessages(_PART_OPERATIONS):
            extents = tuple(
                Extent(e.integer(_EXTENT_START), e.integer(_EXTENT_NUM))
                for e in op.submessages(_OP_DST_EXTENTS)
            )
            operations.append(
                Operation(
                    type=op.integer(_OP_TYPE),
                    data_offset=op.integer(_OP_DATA_OFFSET),
                    data_length=op.integer(_OP_DATA_LENGTH),
                    dst_extents=extents,
                )
            )
        return PartitionEntry(name, size, digest, tuple(operations))

    # ---- extraction -----------------------------------------------------------

    def names(self) -> list[str]:
        return sorted(self.partitions)

    def require(self, name: str) -> PartitionEntry:
        entry = self.partitions.get(name)
        if entry is None:
            raise FirmwareError(
                f"the payload contains no partition named {name!r}",
                remedy=f"It contains: {', '.join(self.names())}",
            )
        return entry

    def extract(self, name: str, dest: Path, *, verify_hash: bool = True) -> Path:
        """Reconstruct one partition image into ``dest``."""
        entry = self.require(name)
        if not entry.is_full:
            raise FirmwareError(
                f"{name} uses delta operations ({', '.join(sorted(entry.unsupported_ops()))})",
                remedy=(
                    "This is an incremental OTA. Download the full firmware package "
                    "instead -- a partially reconstructed image is not safe to trust."
                ),
            )

        dest = Path(dest)
        dest.parent.mkdir(parents=True, exist_ok=True)
        buffer = bytearray(entry.size)

        with open(self.path, "rb") as fh:
            for op in entry.operations:
                chunk = self._apply(fh, op)
                pos = 0
                for extent in op.dst_extents:
                    start = extent.start_block * self.block_size
                    length = extent.num_blocks * self.block_size
                    piece = chunk[pos : pos + length]
                    if start + len(piece) > len(buffer):
                        # Trailing extents can run past the declared size on some
                        # payloads; grow rather than silently truncating.
                        buffer.extend(b"\x00" * (start + len(piece) - len(buffer)))
                    buffer[start : start + len(piece)] = piece
                    pos += length

        data = bytes(buffer[: entry.size]) if entry.size else bytes(buffer)
        if verify_hash and entry.sha256:
            actual = hashlib.sha256(data).hexdigest()
            if actual != entry.sha256:
                raise FirmwareError(
                    f"{name}: extracted image hashes to {actual[:12]} but the payload "
                    f"manifest says {entry.sha256[:12]}",
                    remedy="The download is corrupt. Fetch the firmware again.",
                )
        dest.write_bytes(data)
        return dest

    def _apply(self, fh: BinaryIO, op: Operation) -> bytes:
        if op.type == OP_ZERO:
            total = sum(e.num_blocks for e in op.dst_extents) * self.block_size
            return b"\x00" * total
        fh.seek(self._data_offset + op.data_offset)
        raw = fh.read(op.data_length)
        if len(raw) != op.data_length:
            raise FirmwareError("payload data is truncated")
        if op.type == OP_REPLACE:
            return raw
        if op.type == OP_REPLACE_BZ:
            return bz2.decompress(raw)
        if op.type == OP_REPLACE_XZ:
            return lzma.decompress(raw)
        raise FirmwareError(f"unsupported operation {op.type_name}")
