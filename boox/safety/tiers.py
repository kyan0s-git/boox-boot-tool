"""Blast-radius classification for partitions.

Every write target is assigned a tier, and the tier decides how much ceremony
is required before the bytes go anywhere.  The classification is *fail-closed*:
a partition we do not recognise is treated as CATASTROPHIC, because an unknown
partition could be anything, including part of the boot chain.
"""

from __future__ import annotations

import re
from enum import IntEnum


class Tier(IntEnum):
    """Ordered by how bad it is to get the write wrong."""

    SAFE = 1
    DANGEROUS = 2
    CATASTROPHIC = 3

    @property
    def label(self) -> str:
        return self.name

    @property
    def style(self) -> str:
        return {Tier.SAFE: "ok", Tier.DANGEROUS: "warn", Tier.CATASTROPHIC: "danger"}[self]


# Recoverable by rewriting the partition from a backup; the device still has a
# working boot chain and EDL underneath.
_SAFE = {
    "boot", "init_boot", "recovery", "vendor_boot", "dtbo",
}

# Getting these wrong costs you a boot or a factory reset, but the primary
# bootloader still comes up and EDL is still reachable.
_DANGEROUS = {
    "vbmeta", "vbmeta_system", "vbmeta_vendor", "misc", "frp", "devinfo",
    "metadata", "userdata", "cache", "system", "vendor", "product",
    "super", "vendor_dlkm", "system_ext", "odm",
}

# Damage here can take out the boot chain, the radio, or the calibration data,
# and recovery may need an EDL cable or test points. The abl path lives here.
_CATASTROPHIC = {
    "abl", "xbl", "xbl_config", "xbl_a", "xbl_b", "tz", "hyp", "keymaster",
    "cmnlib", "cmnlib64", "devcfg", "storsec", "uefisecapp", "featenabler",
    "imagefv", "multiimgoem", "qupfw", "aop", "modem", "dsp", "bluetooth",
    "persist", "modemst1", "modemst2", "fsg", "fsc", "sec", "apdp", "msadp",
    "splash", "logo", "rpm", "PrimaryGPT", "BackupGPT", "gpt", "limits",
    "toolsfv", "vm-bootsys", "shrm", "cpucp",
}

_SLOT_SUFFIX = re.compile(r"_[ab]$")


def base_name(partition: str) -> str:
    """Strip an A/B slot suffix: ``boot_a`` -> ``boot``."""
    return _SLOT_SUFFIX.sub("", partition)


def classify(partition: str, overrides: dict[str, str] | None = None) -> Tier:
    """Return the tier for a partition name.

    ``overrides`` comes from the device profile and is keyed by base name.
    An override may only ever make a partition *more* dangerous, never less --
    a profile cannot talk the tool into treating ``abl`` as safe.
    """
    base = base_name(partition)

    if base in _SAFE:
        tier = Tier.SAFE
    elif base in _DANGEROUS:
        tier = Tier.DANGEROUS
    elif base in _CATASTROPHIC:
        tier = Tier.CATASTROPHIC
    else:
        # Fail closed. We do not know what this is, so we assume the worst.
        tier = Tier.CATASTROPHIC

    if overrides:
        raw = overrides.get(base) or overrides.get(partition)
        if raw:
            try:
                requested = Tier[raw.upper()]
            except KeyError as exc:
                raise ValueError(f"unknown tier {raw!r} for partition {partition!r}") from exc
            tier = max(tier, requested)
    return tier


def is_known(partition: str) -> bool:
    """Whether we recognise this partition name at all."""
    base = base_name(partition)
    return base in _SAFE or base in _DANGEROUS or base in _CATASTROPHIC
