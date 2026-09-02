"""Parsing of the Sahara handshake banner that EDL tools print.

Two families of tool are in common use for Boox devices -- bkerler's Python
``edl`` and Renate's Windows ``edl.exe`` -- and they format this information
differently.  We parse both tolerantly, because the values are what bind a
backup to the device it came from, and a missed HWID means we lose that binding.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

_PATTERNS = {
    "hwid": (
        re.compile(r"HWID\s*[:=]\s*(?:0x)?([0-9a-fA-F]{8,20})"),
    ),
    "jtag_id": (
        re.compile(r"JTAG(?:\s*ID)?\s*[:=]\s*(?:0x)?([0-9a-fA-F]{4,16})"),
        re.compile(r"MSM\s*ID\s*[:=]\s*(?:0x)?([0-9a-fA-F]{4,16})"),
    ),
    "pbl_hash": (
        re.compile(r"(?:PK_HASH|PKHASH|Hash)\s*[:=]\s*(?:0x)?([0-9a-fA-F]{16,})"),
    ),
    "serial": (
        re.compile(r"Serial\s*[:=]\s*(?:0x)?([0-9a-fA-F]{4,16})"),
    ),
    "soc": (
        re.compile(r"CPU\s*detected\s*[:=]\s*\"?([^\"\n]+)"),
        re.compile(r"SoC\s*[:=]\s*\"?([^\"\n]+)"),
    ),
}


@dataclass(frozen=True)
class DeviceIdentity:
    """What the boot ROM tells us about the chip we are connected to."""

    hwid: str | None = None
    jtag_id: str | None = None
    pbl_hash: str | None = None
    serial: str | None = None
    soc: str | None = None
    raw: str = ""

    @property
    def known(self) -> bool:
        return bool(self.hwid or self.jtag_id or self.pbl_hash)

    def fingerprint(self) -> str:
        """A stable identifier used to bind a backup to one physical device.

        The PBL hash is chip-model-wide, so it alone cannot distinguish two
        units; the serial can. We include everything we have and compare
        field-by-field rather than as one opaque string.
        """
        parts = [self.hwid or "?", self.jtag_id or "?", self.serial or "?"]
        return "/".join(parts)

    def describe(self) -> str:
        bits = []
        if self.soc:
            bits.append(self.soc)
        if self.hwid:
            bits.append(f"HWID {self.hwid}")
        if self.jtag_id:
            bits.append(f"JTAG {self.jtag_id}")
        if self.serial:
            bits.append(f"serial {self.serial}")
        if self.pbl_hash:
            bits.append(f"PBL hash {self.pbl_hash[:16]}...")
        return ", ".join(bits) if bits else "no identifying information reported"

    def as_dict(self) -> dict[str, str | None]:
        return {
            "hwid": self.hwid,
            "jtag_id": self.jtag_id,
            "pbl_hash": self.pbl_hash,
            "serial": self.serial,
            "soc": self.soc,
        }


def parse(output: str) -> DeviceIdentity:
    """Extract identity fields from an EDL tool's console output."""
    found: dict[str, str] = {}
    for field, patterns in _PATTERNS.items():
        for pattern in patterns:
            m = pattern.search(output)
            if m:
                value = m.group(1).strip()
                found[field] = value.lower() if field != "soc" else value
                break
    return DeviceIdentity(raw=output, **found)


def mismatch(expected: DeviceIdentity, actual: DeviceIdentity) -> list[str]:
    """Report fields that are present in both but disagree.

    A field missing from either side is not a mismatch -- different tools report
    different subsets -- but a field that is present in both and differs means
    this is a different device, and that must stop a write.
    """
    problems: list[str] = []
    for field in ("hwid", "jtag_id", "pbl_hash", "serial"):
        want, got = getattr(expected, field), getattr(actual, field)
        if not (want and got):
            continue
        want, got = want.lower(), got.lower()
        if field == "pbl_hash":
            # Different EDL tools print different amounts of the same hash
            # (Renate's concatenates several blocks, bkerler's prints one), so
            # compare only the length they have in common. Treating that as a
            # mismatch would block legitimate writes.
            n = min(len(want), len(got))
            if want[:n] != got[:n]:
                problems.append(f"{field}: backup says {want}, device reports {got}")
            continue
        if want != got:
            problems.append(f"{field}: backup says {want}, device reports {got}")
    return problems
