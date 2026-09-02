"""An in-process fake device.

This exists so the entire flow -- preflight, backup, verify, write, read-back,
journal recovery -- can be exercised without putting a real tablet at risk, and
so that failure modes we must survive (a flaky cable, a write that silently
lands wrong, a disconnect mid-write) can be reproduced on demand rather than
waited for.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from boox.errors import EdlError
from boox.imaging.gpt import Partition, PartitionTable
from boox.transport.edl import EdlBackend
from boox.transport.sahara import DeviceIdentity

DEFAULT_IDENTITY = DeviceIdentity(
    hwid="0013f0e100000000",
    jtag_id="0013f0e1",
    pbl_hash="d40eee56f3194665574109a39267724a",
    serial="1a2b3c4d",
    soc="MOCK-SM7225",
    raw="mock device",
)


@dataclass
class FaultConfig:
    """Faults to inject. Everything defaults to off."""

    # Raise on the Nth write to this partition (1-based).
    fail_write_on: dict[str, int] = field(default_factory=dict)
    # Write succeeds but stores different bytes -- the case read-back must catch.
    silent_corrupt: set[str] = field(default_factory=set)
    # As above, but only for the next write, so a rollback afterwards succeeds.
    silent_corrupt_once: set[str] = field(default_factory=set)
    # Second read of a partition returns different bytes -- a flaky cable.
    flaky_read: set[str] = field(default_factory=set)
    # Reads return a truncated image.
    short_read: set[str] = field(default_factory=set)
    # Raise EdlError on any operation once this many have run.
    disconnect_after: int | None = None
    # Writes land, then the process "dies" before anything else happens.
    die_after_write: str | None = None


class MockDeviceError(EdlError):
    """Raised by injected faults, so tests can tell them from real bugs."""


class MockBackend(EdlBackend):
    """A file-backed simulated Qualcomm device."""

    name = "mock"

    def __init__(
        self,
        root: Path,
        *,
        identity: DeviceIdentity | None = None,
        faults: FaultConfig | None = None,
        sector_size: int = 512,
    ) -> None:
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        self.identity_value = identity or DEFAULT_IDENTITY
        self.faults = faults or FaultConfig()
        self.sector_size = sector_size
        self.operations = 0
        self.write_counts: dict[str, int] = {}
        self.log: list[tuple[str, str]] = []
        self._layout_path = self.root / "layout.json"
        self._layout: dict[str, int] = {}
        if self._layout_path.exists():
            self._layout = json.loads(self._layout_path.read_text())

    # ---- construction helpers -------------------------------------------------

    def add_partition(self, name: str, content: bytes, size: int | None = None) -> None:
        """Create a partition holding ``content``, zero-padded to ``size``."""
        size = size if size is not None else max(len(content), self.sector_size)
        if len(content) > size:
            raise ValueError(f"{name}: content ({len(content)}) exceeds size ({size})")
        blob = content + b"\x00" * (size - len(content))
        (self.root / f"{name}.img").write_bytes(blob)
        self._layout[name] = size
        self._layout_path.write_text(json.dumps(self._layout, indent=2, sort_keys=True))

    def partition_bytes(self, name: str) -> bytes:
        """Read the stored bytes directly, bypassing fault injection."""
        return (self.root / f"{name}.img").read_bytes()

    # ---- fault plumbing -------------------------------------------------------

    def _tick(self, what: str, partition: str) -> None:
        self.operations += 1
        self.log.append((what, partition))
        limit = self.faults.disconnect_after
        if limit is not None and self.operations > limit:
            raise MockDeviceError(
                "device disconnected",
                remedy="Simulated USB disconnect (fault injection).",
            )

    def _path(self, name: str) -> Path:
        path = self.root / f"{name}.img"
        if not path.exists():
            raise EdlError(f"partition {name!r} does not exist on this device")
        return path

    # ---- EdlBackend -----------------------------------------------------------

    def identify(self) -> DeviceIdentity:
        self._tick("identify", "-")
        return self.identity_value

    def partition_table(self) -> PartitionTable:
        self._tick("gpt", "-")
        parts: list[Partition] = []
        lba = 64
        for name in sorted(self._layout):
            sectors = max(1, self._layout[name] // self.sector_size)
            parts.append(Partition(name, lba, sectors, self.sector_size))
            lba += sectors
        if not parts:
            raise EdlError("mock device has no partitions")
        return PartitionTable(parts, source="mock")

    def read_partition(self, name: str, dest: Path) -> int:
        self._tick("read", name)
        data = self._path(name).read_bytes()
        if name in self.faults.short_read:
            data = data[: len(data) // 3]
        if name in self.faults.flaky_read and self.log.count(("read", name)) > 1:
            data = bytearray(data)
            data[0:4] = b"FLAK"
            data = bytes(data)
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(data)
        return len(data)

    def write_partition(self, name: str, src: Path) -> None:
        self._tick("write", name)
        count = self.write_counts.get(name, 0) + 1
        self.write_counts[name] = count
        if self.faults.fail_write_on.get(name) == count:
            raise MockDeviceError(f"simulated write failure on {name} (attempt {count})")

        path = self._path(name)
        capacity = self._layout[name]
        payload = src.read_bytes()
        if len(payload) > capacity:
            raise EdlError(
                f"{name}: image is {len(payload)} bytes but the partition holds {capacity}"
            )
        if name in self.faults.silent_corrupt_once:
            self.faults.silent_corrupt_once.discard(name)
            payload = b"\xde\xad\xbe\xef" + payload[4:]
        elif name in self.faults.silent_corrupt:
            payload = b"\xde\xad\xbe\xef" + payload[4:]
        path.write_bytes(payload + b"\x00" * (capacity - len(payload)))

        if self.faults.die_after_write == name:
            raise MockDeviceError(f"simulated crash immediately after writing {name}")

    def erase_partition(self, name: str) -> None:
        self._tick("erase", name)
        path = self._path(name)
        path.write_bytes(b"\x00" * self._layout[name])

    def reset(self) -> None:
        self._tick("reset", "-")
