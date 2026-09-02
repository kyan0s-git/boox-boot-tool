"""Full-device backup and restore.

A backup here is a directory of raw partition images plus a ``manifest.json``
that records what device they came from, what the partition table looked like,
and the SHA-256 of every image.  The manifest is what binds the images to one
physical tablet, which is how the verifier can later refuse to write partition
images from device A onto device B.

Every partition is read twice and the two reads compared before it is accepted,
so a backup that verifies is a backup that was actually transferred correctly.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass
from pathlib import Path

from boox import __version__
from boox.console import info, ok, step, warn
from boox.errors import BackupError
from boox.imaging.gpt import PartitionTable
from boox.profiles import Profile
from boox.safety.session import DeviceSession, WriteToken
from boox.safety.tiers import classify
from boox.safety.verify import Reference
from boox.transport.sahara import DeviceIdentity
from boox.util import free_space, human_size, sha256_file, short

MANIFEST_NAME = "manifest.json"
SCHEMA_VERSION = 1
# Refuse to start a backup unless this much headroom remains afterwards.
FREE_SPACE_MARGIN = 512 * 1024 * 1024


@dataclass
class Backup:
    root: Path
    manifest: dict

    # ---- loading --------------------------------------------------------------

    @classmethod
    def load(cls, root: Path) -> "Backup":
        root = Path(root)
        path = root / MANIFEST_NAME
        if not path.is_file():
            raise BackupError(
                f"{root} does not look like a backup ({MANIFEST_NAME} is missing)",
                remedy="Point at the directory 'boox backup' created, not its parent.",
            )
        try:
            manifest = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise BackupError(f"{path} is corrupt: {exc}") from exc
        if manifest.get("schema") != SCHEMA_VERSION:
            warn(f"{path}: schema {manifest.get('schema')}, this tool writes {SCHEMA_VERSION}")
        return cls(root=root, manifest=manifest)

    @classmethod
    def latest(cls, base: Path) -> "Backup | None":
        candidates = sorted(
            (p for p in Path(base).glob("*") if (p / MANIFEST_NAME).is_file()),
            key=lambda p: p.stat().st_mtime,
        )
        return cls.load(candidates[-1]) if candidates else None

    # ---- accessors ------------------------------------------------------------

    @property
    def identity(self) -> DeviceIdentity:
        return DeviceIdentity(**{k: v for k, v in (self.manifest.get("identity") or {}).items()})

    @property
    def profile_id(self) -> str | None:
        return self.manifest.get("profile")

    @property
    def active_slot(self) -> str | None:
        return self.manifest.get("active_slot")

    @property
    def created(self) -> str:
        return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(self.manifest.get("created", 0)))

    def partitions(self) -> dict[str, dict]:
        return self.manifest.get("partitions", {})

    def image(self, partition: str) -> Path | None:
        entry = self.partitions().get(partition)
        if not entry:
            return None
        path = self.root / entry["file"]
        return path if path.is_file() else None

    def reference(self, partition: str) -> Reference | None:
        """This backup's copy of a partition, as a trusted verifier reference."""
        path = self.image(partition)
        if path is None:
            return None
        return Reference(f"device backup {partition}", path.read_bytes())

    def describe(self) -> str:
        return (
            f"{self.root.name}: {len(self.partitions())} partitions, "
            f"taken {self.created}, device {self.identity.fingerprint()}"
        )

    # ---- integrity ------------------------------------------------------------

    def verify(self) -> list[str]:
        """Re-hash every image against the manifest. Returns a list of problems."""
        problems: list[str] = []
        for name, entry in sorted(self.partitions().items()):
            path = self.root / entry["file"]
            if not path.is_file():
                problems.append(f"{name}: image file is missing")
                continue
            actual = sha256_file(path)
            if actual != entry["sha256"]:
                problems.append(
                    f"{name}: sha256 is {short(actual)}, manifest says {short(entry['sha256'])}"
                )
        return problems

    def require_intact(self) -> None:
        problems = self.verify()
        if problems:
            raise BackupError(
                "this backup does not match its own manifest:\n  " + "\n  ".join(problems),
                remedy="Do not restore from it. Take a fresh backup while the device still boots.",
            )


def _estimate_size(table: PartitionTable, wanted: list[str]) -> int:
    return sum(p.size_bytes for p in table if p.name in set(wanted))


def create(
    session: DeviceSession,
    profile: Profile,
    dest: Path,
    *,
    partitions: list[str] | None = None,
    adb_props: dict | None = None,
) -> Backup:
    """Read the profile's backup set off the device and write a verified backup."""
    dest = Path(dest)
    table = session.table
    wanted = list(partitions or profile.backup_set)

    present = [name for name in wanted if name in table]
    missing = [name for name in wanted if name not in table]
    if not present:
        raise BackupError(
            "none of the partitions this profile wants to back up exist on the device",
            remedy=(
                "The profile may be for a different model, or the partition table was "
                "read incorrectly. Check 'boox doctor' output before going further."
            ),
        )
    if missing:
        # Not fatal: profiles list a superset so one file covers several models.
        info(f"not present on this device, skipping: {', '.join(missing)}")

    needed = _estimate_size(table, present)
    available = free_space(dest)
    if available < needed + FREE_SPACE_MARGIN:
        raise BackupError(
            f"not enough disk space: need about {human_size(needed)} plus headroom, "
            f"{human_size(available)} free at {dest}",
            remedy="Free up space or pass --dest pointing somewhere larger.",
        )

    dest.mkdir(parents=True, exist_ok=True)
    step(f"backing up {len(present)} partitions to {dest} ({human_size(needed)})")

    entries: dict[str, dict] = {}
    for name in present:
        path, digest = session.read_twice(name)
        final = dest / f"{name}.img"
        if path.resolve() != final.resolve():
            final.write_bytes(path.read_bytes())
            path.unlink(missing_ok=True)
        entries[name] = {
            "file": final.name,
            "sha256": digest,
            "size": final.stat().st_size,
            "tier": classify(name, profile.tier_overrides).label,
        }
        info(f"{name}: {human_size(final.stat().st_size)}  {short(digest)}")

    manifest = {
        "schema": SCHEMA_VERSION,
        "tool_version": __version__,
        "created": time.time(),
        "profile": profile.id,
        "profile_verified": profile.verified,
        "identity": session.identity.as_dict(),
        "adb": adb_props or {},
        "active_slot": (adb_props or {}).get("active_slot"),
        "memory": profile.memory,
        "partition_table": [
            {
                "name": p.name,
                "start_lba": p.start_lba,
                "sectors": p.sector_count,
                "sector_size": p.sector_size,
            }
            for p in table
        ],
        "partitions": entries,
    }
    (dest / MANIFEST_NAME).write_text(json.dumps(manifest, indent=2, sort_keys=True))

    backup = Backup(root=dest, manifest=manifest)
    backup.require_intact()
    ok(f"backup complete and verified: {dest}")
    return backup


def restore(
    session: DeviceSession,
    backup: Backup,
    token: WriteToken,
    partitions: list[str],
    *,
    profile: Profile | None = None,
) -> None:
    """Write partitions back from a backup, after proving it is the same device."""
    from boox.safety.verify import verify_candidate  # local import: avoids a cycle

    backup.require_intact()
    session.require_same_device(backup.identity)

    for name in partitions:
        image = backup.image(name)
        if image is None:
            raise BackupError(f"this backup has no copy of {name}")
        report = verify_candidate(
            image.read_bytes(),
            target=name,
            table=session.table,
            references=[Reference(f"device backup {name}", image.read_bytes())],
            require_root_patch=False,
            expect_identity=backup.identity,
            actual_identity=session.identity,
        )
        session.write(
            name,
            image,
            token=token,
            report=report,
            backup=image,
            tier_overrides=(profile.tier_overrides if profile else None),
        )
