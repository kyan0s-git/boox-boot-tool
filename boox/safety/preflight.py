"""Preflight: prove the escape hatch before you need it.

The reasoning here is the whole design of this tool in miniature.  If something
goes wrong during a write, the only way out is to write the partition again from
a backup over EDL.  So before we take any risk, we confirm -- on this device,
with this cable, in this session -- that reading works, that reading is *stable*,
and that writing works.  We prove the write path by rewriting a partition with
the bytes it already contains, which changes nothing but exercises every step of
the recovery procedure while the device is still healthy.

Only if all of that passes does preflight issue a :class:`WriteToken`.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from boox.console import info, step
from boox.errors import PreflightError
from boox.profiles import Profile
from boox.safety.backup import Backup
from boox.safety.journal import Journal
from boox.safety.session import DeviceSession, WriteToken
from boox.safety.verify import Check
from boox.transport.adb import DeviceProps
from boox.util import human_size, sha256_file, short


@dataclass
class PreflightResult:
    checks: list[Check] = field(default_factory=list)
    token: WriteToken | None = None
    observed_hwid: str | None = None

    def add(self, name: str, passed: bool, detail: str, *, fatal: bool = True) -> None:
        self.checks.append(Check(name, passed, detail, fatal))

    @property
    def failures(self) -> list[Check]:
        return [c for c in self.checks if not c.passed and c.fatal]

    @property
    def warnings(self) -> list[Check]:
        return [c for c in self.checks if not c.passed and not c.fatal]

    @property
    def ok(self) -> bool:
        return not self.failures

    def render(self) -> str:
        return "\n".join(f"  [{c.symbol:>4}] {c.name}: {c.detail}" for c in self.checks)

    def raise_if_failed(self) -> None:
        if self.ok:
            return
        raise PreflightError(
            "preflight did not pass, so no write will be permitted:\n"
            + "\n".join(f"  - {c.name}: {c.detail}" for c in self.failures),
            remedy="Nothing has been written. Resolve the items above and run it again.",
        )


def run(
    session: DeviceSession,
    profile: Profile,
    journal: Journal,
    *,
    adb_props: DeviceProps | None = None,
    backup: Backup | None = None,
    golden_available: bool = False,
    prove_write: bool = True,
) -> PreflightResult:
    """Run the pre-write checks. Returns a token only if every fatal check passed."""
    result = PreflightResult()

    # --- 1. is this the device the profile is for? ----------------------------
    if adb_props is not None:
        claimed = [m.strip().lower() for m in profile.adb_models]
        matched = adb_props.model.strip().lower() in claimed
        result.add(
            "profile_matches_device",
            matched,
            f"device reports {adb_props.model!r}; profile expects one of {profile.adb_models}",
            fatal=False,
        )
        info(f"device: {adb_props.describe()}")
    else:
        result.add(
            "profile_matches_device", True,
            "no adb connection; model not cross-checked", fatal=False,
        )

    # --- 2. EDL is alive and the loader was accepted --------------------------
    try:
        identity = session.identity
    except Exception as exc:
        result.add("edl_handshake", False, f"could not reach the device over EDL: {exc}")
        return result
    result.add(
        "edl_handshake",
        identity.known,
        identity.describe() if identity.known
        else "the tool connected but reported no HWID; the loader may be wrong for this SoC",
    )
    result.observed_hwid = identity.hwid

    if profile.expected_hwids:
        matched = (identity.hwid or "").lower() in profile.expected_hwids
        result.add(
            "hwid_matches_profile",
            matched,
            f"device HWID {identity.hwid} vs profile {list(profile.expected_hwids)}",
        )
    else:
        result.add(
            "hwid_matches_profile", True,
            f"profile records no expected HWID; observed {identity.hwid}. "
            "Add this to the profile once you have confirmed the device works.",
            fatal=False,
        )

    # --- 3. the partition table is readable and looks like this device --------
    try:
        table = session.table
    except Exception as exc:
        result.add("partition_table", False, f"could not read the partition table: {exc}")
        return result
    result.add("partition_table", len(table) > 0, f"{len(table)} partitions via {table.source}")

    root_target = next((t for t in profile.root_targets
                        if t in table.base_names() or t in table), None)
    result.add(
        "root_target_present",
        root_target is not None,
        f"will patch {root_target!r}" if root_target
        else f"none of {profile.root_targets} exist on this device",
        fatal=False,
    )

    roundtrip = profile.roundtrip_partition
    if roundtrip not in table:
        result.add(
            "roundtrip_partition_present", False,
            f"{roundtrip!r} is not on this device, so the write path cannot be proven",
        )
        return result
    part = table.require(roundtrip)
    result.add(
        "roundtrip_partition_present", True,
        f"{roundtrip} is {human_size(part.size_bytes)}",
    )

    # --- 4. no half-finished operation from a previous run --------------------
    unfinished = journal.unfinished()
    result.add(
        "journal_clean",
        not unfinished,
        "no interrupted operations"
        if not unfinished
        else "previous run left these unfinished: "
             + ", ".join(f"{e.op} {e.partition}" for e in unfinished),
    )

    # --- 5. reading works, and reading is stable ------------------------------
    step(f"proving the read path on {roundtrip}")
    try:
        original, digest = session.read_twice(roundtrip)
    except Exception as exc:
        result.add("read_roundtrip", False, str(exc))
        return result
    result.add(
        "read_roundtrip", True,
        f"two reads of {roundtrip} agree ({short(digest)}, {human_size(original.stat().st_size)})",
    )

    # --- 6. writing works ------------------------------------------------------
    if not prove_write:
        result.add(
            "write_roundtrip", True,
            "skipped (read-only check); no write token will be issued", fatal=False,
        )
        return result

    step(f"proving the write path by rewriting {roundtrip} with its own contents")
    entry = journal.begin(
        "preflight_write_roundtrip", roundtrip, source_sha256=digest, dry_run=session.dry_run
    )
    try:
        if session.dry_run:
            info(f"dry run: would rewrite {roundtrip} with its own {human_size(original.stat().st_size)}")
            journal.done(entry, dry_run=True)
            result.add(
                "write_roundtrip", True, "skipped in dry-run mode; no token issued", fatal=False
            )
            return result

        session.backend.write_partition(roundtrip, original)
        after = session.read(roundtrip, session.workdir / f"{roundtrip}.after.img")
        after_digest = sha256_file(after)
        after.unlink(missing_ok=True)
    except Exception as exc:
        journal.failed(entry, f"preflight write round-trip failed: {exc}")
        result.add(
            "write_roundtrip", False,
            f"could not rewrite {roundtrip}: {exc}. "
            "If a real write had failed this way mid-flash, recovery would not have worked.",
        )
        return result

    if after_digest != digest:
        journal.failed(entry, "content changed after rewriting identical bytes")
        result.add(
            "write_roundtrip", False,
            f"{roundtrip} reads back as {short(after_digest)} after being rewritten with "
            f"{short(digest)} -- writes are not landing correctly on this link",
        )
        return result

    journal.done(entry, readback_sha256=after_digest)
    result.add("write_roundtrip", True, f"{roundtrip} rewritten and verified byte-for-byte")

    # --- 7. what do we have to fall back to? ----------------------------------
    result.add(
        "backup_available",
        backup is not None,
        backup.describe() if backup else "no verified backup in this session",
    )
    result.add(
        "golden_firmware_available",
        golden_available,
        "decrypted stock firmware is available as a second restore source"
        if golden_available
        else "no stock firmware available; the device backup is the only restore source",
        fatal=False,
    )

    if not result.ok:
        return result

    result.token = WriteToken(
        profile_id=profile.id,
        identity=identity,
        read_roundtrip_proven=True,
        write_roundtrip_proven=True,
        backup_taken=backup is not None,
        golden_firmware_available=golden_available,
    )
    return result
