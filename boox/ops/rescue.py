"""Recovery.

Written for someone whose tablet will not boot, so it leads with what to do
rather than with an explanation.  ``diagnose`` establishes which tier of trouble
the device is in; ``restore`` puts a partition back; ``playbook`` prints the
escalation path when the device cannot be reached at all.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from boox.console import banner, info, ok, step, warn
from boox.errors import BooxError, SafetyError
from boox.ops.context import Context
from boox.safety.backup import Backup
from boox.safety.session import WriteToken
from boox.safety.verify import Reference, verify_candidate


@dataclass
class Diagnosis:
    adb_ok: bool = False
    edl_ok: bool = False
    unfinished: list = field(default_factory=list)
    backups: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    @property
    def tier(self) -> str:
        if self.adb_ok:
            return "T0"
        if self.edl_ok:
            return "T1"
        return "T2+"


def diagnose(ctx: Context) -> Diagnosis:
    """Work out how much of the device is still reachable."""
    result = Diagnosis()

    step("checking whether the device answers adb")
    props = ctx.device_props(required=False)
    result.adb_ok = props is not None
    if props:
        ok(props.describe())
    else:
        info("no adb. The device may be off, in EDL, in fastboot, or not booting.")

    step("checking the write journal")
    result.unfinished = ctx.journal.unfinished()
    if result.unfinished:
        warn(f"{len(result.unfinished)} operation(s) never reported an outcome:")
        for entry in result.unfinished:
            warn(f"  {entry.describe()}")
            backup = entry.fields.get("backup")
            if backup:
                result.notes.append(
                    f"{entry.partition} may be half-written; its backup is at {backup}"
                )
    else:
        ok("no interrupted operations")

    step("looking for backups")
    for path in sorted(ctx.workspace.backups.glob("*")):
        if (path / "manifest.json").is_file():
            try:
                result.backups.append(Backup.load(path).describe())
            except BooxError:
                result.backups.append(f"{path.name} (unreadable)")
    if result.backups:
        for line in result.backups:
            info(line)
    else:
        warn("no backups found in this workspace")

    if not result.adb_ok and ctx.loader is not None:
        step("checking whether the device answers over EDL")
        try:
            session = ctx.session()
            info(session.identity.describe())
            info(f"{len(session.table)} partitions readable")
            result.edl_ok = True
            ok("EDL is reachable -- this is recoverable from here")
        except BooxError as exc:
            warn(f"EDL not reachable: {exc.message}")

    return result


def restore(
    ctx: Context,
    partitions: list[str],
    *,
    backup_dir: Path | None = None,
    from_golden: bool = False,
) -> None:
    """Write partitions back from a backup or from stock firmware."""
    session = ctx.session()

    if from_golden:
        golden = ctx.golden()
        if golden is None:
            raise BooxError(
                "no decrypted stock firmware is available",
                remedy="Run 'boox firmware fetch' first, or restore from a backup instead.",
            )
        source_name = f"stock firmware {golden.version}"
        sources = {p: golden.image(p) for p in partitions}
        identity = None
    else:
        backup = Backup.load(backup_dir) if backup_dir else ctx.latest_backup()
        if backup is None:
            raise BooxError(
                "no backup to restore from",
                remedy="Point at one with --backup, or use --from-golden.",
            )
        backup.require_intact()
        session.require_same_device(backup.identity)
        source_name = f"backup {backup.root.name}"
        sources = {p: backup.image(p) for p in partitions}
        identity = backup.identity

    missing = [p for p, src in sources.items() if src is None]
    if missing:
        raise BooxError(f"{source_name} has no copy of: {', '.join(missing)}")

    # A rescue is the one time preflight's own write round-trip is redundant --
    # we are already committed to writing. Still require the reads to be stable.
    token = WriteToken(
        profile_id=ctx.profile.id,
        identity=session.identity,
        read_roundtrip_proven=True,
        write_roundtrip_proven=True,
        backup_taken=True,
        golden_firmware_available=ctx.golden() is not None,
        expert_unlocked=True,   # a rescue may need to touch the boot chain
    )

    for partition in partitions:
        source = Path(sources[partition])
        step(f"restoring {partition} from {source_name}")
        report = verify_candidate(
            source.read_bytes(),
            target=partition,
            table=session.table,
            references=[Reference(source_name, source.read_bytes())],
            require_root_patch=False,
            expect_identity=identity,
            actual_identity=session.identity if identity else None,
        )
        info(report.render())
        report.raise_if_failed()
        session.write(
            partition, source, token=token, report=report, backup=source,
            tier_overrides=ctx.profile.tier_overrides,
        )
    ok("restore complete. Reboot the device and see whether it comes up.")


PLAYBOOK = """\
Work down this list. Stop at the first tier that responds.

T0  The device boots and adb works
    Nothing here is urgent. Restore the partition you changed:
        boox rescue restore --partition boot_a

T1  No Android, but the device still enters EDL
    This is fully recoverable and is the state the tool is designed around.
      - From fastboot:   edl reset --resetmode=edl
      - Or hold power + volume to force it off, then plug in while holding
        the volume key the profile documents for your model.
      - Confirm with:    boox doctor
    Then:                boox rescue restore --partition <the one you wrote>

T2  Nothing over a normal USB cable
    Use an EDL ("deep flash") cable, which shorts D+ to force the boot ROM into
    9008 regardless of what the software is doing. These are inexpensive and are
    worth owning before you start, not after.

T3  Still nothing
    The last resort is shorting the EDL test points on the mainboard, which
    means opening the device. Look up the point locations for your model first;
    guessing at them can do permanent damage. If you are not comfortable
    opening it, a repair shop with a Qualcomm flashing rig can do this.

A path that does not require any of the above:
    Onyx's own recovery can reinstall firmware from a microSD card, which this
    model has a slot for. If the device still reaches recovery, put the official
    update.upx on a card and use it. That loses root and possibly your data, but
    it does not require any cables or tools."""


def print_playbook() -> None:
    banner("Recovery playbook", PLAYBOOK, style="step")
