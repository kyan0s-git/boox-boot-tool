"""GPT partition table model and parsers.

Three sources are supported, in descending order of trustworthiness:

1. A raw GPT dump (``EFI PART``) -- authoritative, so this is what we prefer.
2. A ``rawprogram*.xml`` emitted by edl -- machine readable and stable.
3. The text table printed by ``edl printgpt`` -- a last resort, parsed
   tolerantly because its formatting varies between edl versions.

Whichever source is used, the result is the same :class:`PartitionTable`, and
every later safety check reads partition bounds from it.
"""

from __future__ import annotations

import re
import struct
import xml.etree.ElementTree as ET
from dataclasses import dataclass

from boox.errors import ImageError

GPT_SIGNATURE = b"EFI PART"
_SLOT_RE = re.compile(r"^(?P<base>.+)_(?P<slot>[ab])$")


@dataclass(frozen=True)
class Partition:
    name: str
    start_lba: int
    sector_count: int
    sector_size: int
    lun: int = 0

    @property
    def size_bytes(self) -> int:
        return self.sector_count * self.sector_size

    @property
    def base_name(self) -> str:
        """``boot_a`` -> ``boot``; unslotted names are returned unchanged."""
        m = _SLOT_RE.match(self.name)
        return m.group("base") if m else self.name

    @property
    def slot(self) -> str | None:
        m = _SLOT_RE.match(self.name)
        return m.group("slot") if m else None


@dataclass
class PartitionTable:
    partitions: list[Partition]
    source: str = "unknown"

    def __post_init__(self) -> None:
        self._by_name = {p.name: p for p in self.partitions}

    def __contains__(self, name: str) -> bool:
        return name in self._by_name

    def __len__(self) -> int:
        return len(self.partitions)

    def __iter__(self):
        return iter(self.partitions)

    def get(self, name: str) -> Partition | None:
        return self._by_name.get(name)

    def require(self, name: str) -> Partition:
        part = self._by_name.get(name)
        if part is None:
            close = ", ".join(sorted(n for n in self._by_name if n.startswith(name[:4]))) or "none"
            raise ImageError(
                f"partition {name!r} is not in this device's partition table",
                remedy=f"Similar names present: {close}",
            )
        return part

    def names(self) -> list[str]:
        return [p.name for p in self.partitions]

    def base_names(self) -> set[str]:
        return {p.base_name for p in self.partitions}

    def slots(self) -> set[str]:
        return {p.slot for p in self.partitions if p.slot}

    def is_ab(self) -> bool:
        return {"a", "b"}.issubset(self.slots())

    def resolve(self, base: str, slot: str | None) -> Partition:
        """Resolve a base name plus slot suffix to a concrete partition.

        Never guesses: if the table is A/B and no slot was given for a slotted
        partition, that is an error, because silently picking the wrong slot is
        one of the two documented ways people have bricked these devices.
        """
        if base in self._by_name:
            return self._by_name[base]
        if slot is None:
            candidates = sorted(n for n in self._by_name if _SLOT_RE.match(n) and
                                _SLOT_RE.match(n).group("base") == base)
            if candidates:
                raise ImageError(
                    f"{base!r} is a slotted partition ({', '.join(candidates)}) "
                    "but no slot was resolved",
                    remedy="Determine the active slot before writing. Refusing to guess.",
                )
            raise ImageError(f"partition {base!r} not found")
        return self.require(f"{base}_{slot}")


def parse_gpt_binary(data: bytes) -> PartitionTable:
    """Parse a raw GPT dump. Handles 512- and 4096-byte sectors."""
    for sector_size in (512, 4096):
        header_off = sector_size
        if len(data) < header_off + 92:
            continue
        if data[header_off : header_off + 8] != GPT_SIGNATURE:
            continue
        return _parse_gpt_at(data, header_off, sector_size)
    # Some dumps start at the GPT header itself rather than at the protective MBR.
    if data.startswith(GPT_SIGNATURE):
        return _parse_gpt_at(data, 0, 512, entries_follow_header=True)
    raise ImageError(
        "no GPT header found ('EFI PART' magic missing)",
        remedy="The dump may be truncated, or this device may not use GPT.",
    )


def _parse_gpt_at(
    data: bytes, header_off: int, sector_size: int, *, entries_follow_header: bool = False
) -> PartitionTable:
    entry_lba, num_entries, entry_size = struct.unpack_from("<QII", data, header_off + 72)
    if not (0 < num_entries <= 4096):
        raise ImageError(f"implausible GPT entry count {num_entries}")
    if not (128 <= entry_size <= 4096):
        raise ImageError(f"implausible GPT entry size {entry_size}")

    if entries_follow_header:
        base = header_off + sector_size
    else:
        base = entry_lba * sector_size
    partitions: list[Partition] = []
    for i in range(num_entries):
        off = base + i * entry_size
        if off + entry_size > len(data):
            break
        type_guid = data[off : off + 16]
        if type_guid == b"\x00" * 16:
            continue
        start_lba, end_lba = struct.unpack_from("<QQ", data, off + 32)
        name = data[off + 56 : off + 128].decode("utf-16-le", "replace").split("\x00", 1)[0]
        if not name:
            continue
        partitions.append(
            Partition(
                name=name,
                start_lba=start_lba,
                sector_count=max(0, end_lba - start_lba + 1),
                sector_size=sector_size,
            )
        )
    if not partitions:
        raise ImageError("GPT parsed but contained no usable partition entries")
    return PartitionTable(partitions, source="gpt-binary")


def parse_rawprogram_xml(sources: dict[str, str]) -> PartitionTable:
    """Parse one or more ``rawprogram<lun>.xml`` documents keyed by filename."""
    partitions: list[Partition] = []
    for filename, text in sorted(sources.items()):
        lun_match = re.search(r"(\d+)", filename)
        default_lun = int(lun_match.group(1)) if lun_match else 0
        try:
            root = ET.fromstring(text)
        except ET.ParseError as exc:
            raise ImageError(f"could not parse {filename}: {exc}") from exc
        for prog in root.iter("program"):
            label = prog.get("label")
            if not label:
                continue
            try:
                sector_size = int(prog.get("SECTOR_SIZE_IN_BYTES", "512"))
                start = int(str(prog.get("start_sector", "0")).split(".")[0])
                count = int(prog.get("num_partition_sectors", "0"))
            except ValueError:
                continue
            lun = int(prog.get("physical_partition_number", default_lun) or default_lun)
            partitions.append(Partition(label, start, count, sector_size, lun))
    if not partitions:
        raise ImageError("no <program> entries found in the rawprogram XML")
    return PartitionTable(partitions, source="rawprogram-xml")


_PRINTGPT_ROW = re.compile(
    r"^\s*(?P<name>[A-Za-z0-9_.\-]+)\s*:?\s+"
    r"(?:Offset|start)?\s*0x(?P<start>[0-9a-fA-F]+)\s*,?\s+"
    r"(?:Length|size)?\s*0x(?P<length>[0-9a-fA-F]+)",
)


def parse_printgpt_text(text: str, sector_size: int = 512) -> PartitionTable:
    """Best-effort parse of edl's human-readable partition table.

    Offsets and lengths in that output are byte values, not sectors.
    """
    partitions: list[Partition] = []
    for line in text.splitlines():
        m = _PRINTGPT_ROW.match(line)
        if not m:
            continue
        name = m.group("name")
        if name.lower() in {"gpt", "total", "partition"}:
            continue
        start = int(m.group("start"), 16)
        length = int(m.group("length"), 16)
        if length <= 0:
            continue
        partitions.append(
            Partition(name, start // sector_size, length // sector_size, sector_size)
        )
    if not partitions:
        raise ImageError(
            "could not parse any partitions out of the edl output",
            remedy="Run with --debug to see the raw output, and report it as a bug.",
        )
    return PartitionTable(partitions, source="printgpt-text")
