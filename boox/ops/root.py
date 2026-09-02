"""Rooting: patch the ramdisk-bearing boot image with Magisk and write it back.

Split into two phases because Magisk does the patching *on the tablet*, which
means the device has to leave EDL and come back:

* ``prepare`` -- back up, fetch the stock reference, work out which partition
  and which slot to touch, and put the stock image on the device.
* ``apply``   -- collect what Magisk produced, verify it hard, and write it.

They are separate commands as well as steps in the wizard, so an interrupted
run can be picked up rather than restarted.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass
from pathlib import Path

from boox.console import banner, info, ok, step, warn
from boox.errors import BooxError, SafetyError
from boox.imaging import bootimg
from boox.ops.context import Context
from boox.safety import preflight
from boox.safety.backup import Backup, create as create_backup
from boox.safety.verify import verify_candidate
from boox.util import human_size, sha256_file, short

DEVICE_STAGING = "/sdcard/Download"
STATE_FILE = "root-state.json"


@dataclass
class RootPlan:
    """What ``apply`` needs to know, carried between the two phases."""

    partition: str          # concrete, slot suffix included
    base: str               # "boot" or "init_boot"
    slot: str | None
    stock_image: Path
    backup_dir: Path
    device_path: str

    def to_json(self) -> dict:
        return {
            "partition": self.partition,
            "base": self.base,
            "slot": self.slot,
            "stock_image": str(self.stock_image),
            "backup_dir": str(self.backup_dir),
            "device_path": self.device_path,
            "created": time.time(),
        }

    @classmethod
    def from_json(cls, data: dict) -> "RootPlan":
        return cls(
            partition=data["partition"],
            base=data["base"],
            slot=data.get("slot"),
            stock_image=Path(data["stock_image"]),
            backup_dir=Path(data["backup_dir"]),
            device_path=data["device_path"],
        )


def choose_target(ctx: Context, session, slot: str | None) -> tuple[str, str]:
    """Pick the partition Magisk should patch, by looking at what is really there.

    Devices that launched on Android 13 keep the ramdisk in ``init_boot`` and
    leave ``boot`` holding only the kernel; older layouts keep both in ``boot``.
    Rather than trust the profile, read the candidate images and use whichever
    actually carries a ramdisk.
    """
    table = session.table
    for base in ctx.profile.root_targets:
        name = f"{base}_{slot}" if slot and f"{base}_{slot}" in table else base
        if name not in table:
            continue
        try:
            image = session.read(name, session.workdir / f"probe-{name}.img")
            parsed = bootimg.parse(image.read_bytes(), allow_empty_kernel=True)
        except BooxError as exc:
            info(f"{name}: not a readable boot image ({exc}); trying the next candidate")
            continue
        if parsed.ramdisk:
            info(f"{name} carries a {human_size(len(parsed.ramdisk))} ramdisk; patching that")
            return base, name
        info(f"{name} has no ramdisk (kernel-only); trying the next candidate")
    raise SafetyError(
        f"none of {ctx.profile.root_targets} on this device carries a ramdisk",
        remedy=(
            "Magisk has nothing to patch. Check the partition table with "
            "'boox doctor' and report this device layout as a bug."
        ),
    )


def prepare(
    ctx: Context,
    *,
    partitions: list[str] | None = None,
    skip_backup: bool = False,
) -> RootPlan:
    """Back up, choose the target, and stage the stock image on the device."""
    props = ctx.device_props(required=True)
    slot = props.active_slot
    if slot:
        info(f"device is booted from slot {slot}; only that slot will be written")
    else:
        warn("could not determine the active slot; this device may not be A/B")

    ctx.enter_edl()
    session = ctx.session()
    info(f"EDL: {session.identity.describe()}")

    if skip_backup:
        backup = ctx.latest_backup()
        if backup is None:
            raise SafetyError(
                "--skip-backup was given but there is no earlier backup to fall back on",
                remedy="Drop --skip-backup and let it take one.",
            )
        warn(f"reusing the existing backup from {backup.created}")
    else:
        backup_dir = ctx.workspace.new_backup_dir(ctx.profile.id)
        backup = create_backup(
            session, ctx.profile, backup_dir,
            partitions=partitions,
            adb_props={
                "model": props.model,
                "device": props.device,
                "fingerprint": props.build_fingerprint,
                "android_version": props.android_version,
                "security_patch": props.security_patch,
                "active_slot": slot,
                "serial": props.serial,
            },
        )

    base, partition = choose_target(ctx, session, slot)

    stock = ctx.workspace.work / f"stock-{partition}.img"
    from_backup = backup.image(partition)
    if from_backup is not None:
        stock.write_bytes(from_backup.read_bytes())
    else:
        session.read(partition, stock)
    ok(f"stock {partition}: {human_size(stock.stat().st_size)}  {short(sha256_file(stock))}")

    step("rebooting back into Android so Magisk can patch the image")
    session.reset()
    _wait_for_adb(ctx)

    device_path = f"{DEVICE_STAGING}/boox-stock-{partition}.img"
    ctx.adb.push(stock, device_path)

    plan = RootPlan(
        partition=partition, base=base, slot=slot, stock_image=stock,
        backup_dir=backup.root, device_path=device_path,
    )
    (ctx.workspace.work / STATE_FILE).write_text(json.dumps(plan.to_json(), indent=2))

    banner(
        "Now patch the image on the tablet",
        f"1. Open Magisk on the device (install it from github.com/topjohnwu/Magisk if needed)\n"
        f"2. Install -> Select and Patch a File\n"
        f"3. Choose:  {device_path}\n"
        f"4. Let it finish, then run:  boox root apply\n\n"
        f"Patch only this one file. Do not patch anything from another device or slot --\n"
        f"the verifier will reject it, but it is easier not to make the mistake.",
        style="step",
    )
    return plan


def load_plan(ctx: Context) -> RootPlan:
    path = ctx.workspace.work / STATE_FILE
    if not path.is_file():
        raise BooxError(
            "no prepared rooting session was found",
            remedy="Run 'boox root prepare' first.",
        )
    return RootPlan.from_json(json.loads(path.read_text()))


def find_patched_image(ctx: Context, plan: RootPlan) -> str:
    """Locate the file Magisk produced, which gets a random suffix each time."""
    candidates = [
        name for name in ctx.adb.list_dir(DEVICE_STAGING)
        if name.startswith("magisk_patched") and name.endswith(".img")
    ]
    if not candidates:
        raise BooxError(
            f"no magisk_patched-*.img in {DEVICE_STAGING} on the device",
            remedy=(
                f"Patch {plan.device_path} in the Magisk app first "
                "(Install -> Select and Patch a File)."
            ),
        )
    if len(candidates) > 1:
        raise BooxError(
            f"several patched images are present: {', '.join(sorted(candidates))}",
            remedy=(
                "Delete the ones from earlier attempts so there is no doubt which "
                "belongs to this run, then try again."
            ),
        )
    return f"{DEVICE_STAGING}/{candidates[0]}"


def apply(
    ctx: Context,
    *,
    patched: Path | None = None,
    allow_missing_golden: bool = False,
    both_slots: bool = False,
) -> None:
    """Verify what Magisk produced and write it to the active slot.

    ``both_slots`` writes the inactive slot as well. That removes the untouched
    stock copy which is otherwise your fallback, so it is opt-in and warns.
    """
    plan = load_plan(ctx)

    if patched is None:
        remote = find_patched_image(ctx, plan)
        local = ctx.workspace.work / f"patched-{plan.partition}.img"
        info(f"collecting {remote}")
        ctx.adb.pull(remote, local)
    else:
        local = Path(patched)
        if not local.is_file():
            raise BooxError(f"patched image not found: {local}")

    ctx.enter_edl()
    session = ctx.session()

    backup = Backup.load(plan.backup_dir)
    backup.require_intact()
    session.require_same_device(backup.identity)

    golden = ctx.golden()
    if golden is None and not allow_missing_golden:
        raise SafetyError(
            "no decrypted stock firmware is available as a second restore source",
            remedy=(
                "Run 'boox firmware fetch' first. If you accept having only the device "
                "backup to fall back on, pass --allow-missing-golden."
            ),
        )

    references = ctx.references(plan.partition)
    if not references:
        raise SafetyError(
            f"nothing trusted to compare {local.name} against",
            remedy="The backup does not contain this partition. Do not write it.",
        )

    step(f"verifying {local.name} against {len(references)} reference image(s)")
    report = verify_candidate(
        local.read_bytes(),
        target=plan.partition,
        table=session.table,
        references=references,
        require_root_patch=True,
        expect_identity=backup.identity,
        actual_identity=session.identity,
    )
    info(report.render())
    report.raise_if_failed()
    for warning in report.warnings:
        warn(f"{warning.name}: {warning.detail}")

    result = preflight.run(
        session, ctx.profile, ctx.journal,
        adb_props=None, backup=backup, golden_available=golden is not None,
    )
    info(result.render())
    result.raise_if_failed()
    assert result.token is not None

    targets = [plan.partition]
    if both_slots and plan.slot:
        other = f"{plan.base}_{'b' if plan.slot == 'a' else 'a'}"
        if other in session.table:
            warn(
                f"--both-slots will also write {other}. That is currently your untouched "
                "stock fallback; after this there is no stock slot left on the device."
            )
            targets.append(other)
        else:
            warn(f"--both-slots was given but {other} is not on this device; ignoring")

    for target in targets:
        if target == plan.partition:
            target_report = report
        else:
            target_report = verify_candidate(
                local.read_bytes(),
                target=target,
                table=session.table,
                references=ctx.references(target) or references,
                require_root_patch=True,
                expect_identity=backup.identity,
                actual_identity=session.identity,
            )
            target_report.raise_if_failed()
        session.write(
            target, local,
            token=result.token, report=target_report,
            backup=backup.image(target),
            tier_overrides=ctx.profile.tier_overrides,
        )

    session.reset()
    (ctx.workspace.work / STATE_FILE).unlink(missing_ok=True)

    notes = [
        f"{plan.partition} now carries the Magisk-patched image.",
        (
            "The other slot is untouched and still stock, which is your fallback."
            if not both_slots
            else "Both slots were written, so there is no stock slot to fall back on."
        ),
        f"Backup: {plan.backup_dir}",
    ]
    if ctx.profile.quirks.get("magisk_splash_hang"):
        notes.append(
            "\nOn this model the Magisk app is expected to hang on its splash screen -- "
            "root itself works. Run 'boox harden --ams-fix' to build the services.jar "
            "module that fixes the app."
        )
    banner("Rooted", "\n".join(notes), style="ok")


def _wait_for_adb(ctx: Context, timeout: int = 180) -> None:
    step("waiting for the device to come back up")
    if ctx.dry_run:
        info("dry run: not waiting")
        return
    deadline = time.time() + timeout
    while time.time() < deadline:
        ctx._props = None
        props = ctx.device_props(required=False)
        if props is not None:
            ok(f"device is back: {props.describe()}")
            return
        time.sleep(5)
    raise BooxError(
        "the device did not come back on adb",
        remedy=(
            "Unlock it and accept the USB debugging prompt if shown. Nothing has been "
            "written, so it is safe to reconnect and run the command again."
        ),
    )
