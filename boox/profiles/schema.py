"""Device profiles: what we know about a given Boox model.

A profile is data, not code, so that adding a device does not mean touching the
safety logic.  The one field that matters most is ``verified``: an unverified
profile can back up, inspect and dry-run, but the write gate refuses it.  That
keeps a well-meaning contributor's untested profile from bricking someone.
"""

from __future__ import annotations

import tomllib
from dataclasses import dataclass, field
from pathlib import Path

from boox.errors import ProfileError

PROFILE_DIR = Path(__file__).parent


@dataclass(frozen=True)
class LoaderCandidate:
    """A Firehose programmer that may work on this device."""

    name: str
    sha256: str | None = None
    url: str | None = None
    notes: str = ""


@dataclass(frozen=True)
class Profile:
    id: str
    name: str
    verified: bool
    soc: str
    memory: str                       # "emmc" or "ufs"
    expected_hwids: tuple[str, ...]
    adb_models: tuple[str, ...]
    onyx_model: str | None
    loaders: tuple[LoaderCandidate, ...]
    backup_set: tuple[str, ...]
    root_targets: tuple[str, ...]     # preference order, e.g. ("init_boot", "boot")
    roundtrip_partition: str
    tier_overrides: dict[str, str] = field(default_factory=dict)
    quirks: dict[str, object] = field(default_factory=dict)
    notes: str = ""

    @property
    def fastboot_usable(self) -> bool:
        return not bool(self.quirks.get("fastboot_broken", False))

    def describe(self) -> str:
        state = "field-verified" if self.verified else "UNVERIFIED (extra confirmation required)"
        return f"{self.name} [{self.id}] - {self.soc}, {self.memory}, {state}"


def _require(data: dict, section: str, key: str, path: Path):
    try:
        return data[section][key]
    except KeyError as exc:
        raise ProfileError(f"{path.name}: missing required [{section}].{key}") from exc


def load_file(path: Path) -> Profile:
    try:
        raw = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise ProfileError(f"could not read profile {path}: {exc}") from exc

    device = raw.get("device", {})
    soc = raw.get("soc", {})
    parts = raw.get("partitions", {})

    memory = soc.get("memory", "emmc")
    if memory not in ("emmc", "ufs"):
        raise ProfileError(f"{path.name}: [soc].memory must be 'emmc' or 'ufs', got {memory!r}")

    loaders = tuple(
        LoaderCandidate(
            name=item.get("name", "unnamed"),
            sha256=(item.get("sha256") or None),
            url=item.get("url"),
            notes=item.get("notes", ""),
        )
        for item in raw.get("loader", {}).get("candidates", [])
    )

    root_targets = tuple(parts.get("root_targets", ("init_boot", "boot")))
    if not root_targets:
        raise ProfileError(f"{path.name}: [partitions].root_targets must not be empty")

    backup_set = tuple(parts.get("backup_set", ()))
    if not backup_set:
        raise ProfileError(f"{path.name}: [partitions].backup_set must not be empty")

    roundtrip = parts.get("roundtrip_partition", "misc")
    if roundtrip not in backup_set:
        # The preflight write test rewrites this partition with its own bytes,
        # so we must be holding a backup of it before that happens.
        raise ProfileError(
            f"{path.name}: roundtrip_partition {roundtrip!r} must also appear in backup_set",
            remedy="The preflight write test rewrites that partition, so it must be backed up.",
        )

    profile = Profile(
        id=_require(raw, "device", "id", path),
        name=_require(raw, "device", "name", path),
        verified=bool(device.get("verified", False)),
        soc=soc.get("name", "unknown"),
        memory=memory,
        expected_hwids=tuple(h.lower() for h in soc.get("expected_hwids", ())),
        adb_models=tuple(device.get("adb_models", ())),
        onyx_model=raw.get("firmware", {}).get("onyx_model"),
        loaders=loaders,
        backup_set=backup_set,
        root_targets=root_targets,
        roundtrip_partition=roundtrip,
        tier_overrides=dict(parts.get("tier_overrides", {})),
        quirks=dict(raw.get("quirks", {})),
        notes=raw.get("device", {}).get("notes", ""),
    )

    return profile


def available() -> dict[str, Path]:
    """Map profile id -> path for every shipped profile."""
    out: dict[str, Path] = {}
    for path in sorted(PROFILE_DIR.glob("*.toml")):
        if path.stem.startswith("_"):
            continue
        out[path.stem] = path
    return out


def load(profile_id: str) -> Profile:
    paths = available()
    if profile_id not in paths:
        known = ", ".join(sorted(paths)) or "none"
        raise ProfileError(
            f"no profile named {profile_id!r}",
            remedy=f"Known profiles: {known}. Run 'boox profile list'.",
        )
    return load_file(paths[profile_id])


def load_all() -> list[Profile]:
    return [load_file(p) for p in available().values()]


def match_adb_model(model: str) -> Profile | None:
    """Find the profile claiming this ``ro.product.model`` value."""
    needle = model.strip().lower()
    for profile in load_all():
        if any(needle == m.strip().lower() for m in profile.adb_models):
            return profile
    return None
