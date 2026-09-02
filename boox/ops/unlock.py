"""Bootloader unlock via a foreign ABL. The most dangerous thing this tool does.

Onyx's own fastboot is broken on this device -- ``flash`` answers "unknown
command" and ``oem unlock`` reports OKAY while changing nothing -- so the
community route to a working, unlocked fastboot is to write a *different
vendor's* bootloader (a FairPhone 4 ABL, same SoC family) over abl_a/abl_b,
write an FRP unlock blob, and erase devinfo.

That is a foreign bootloader on the boot chain. It cannot be verified against
any reference for this device, because by definition it did not come from one.
If it is wrong, the device will not reach fastboot or recovery, and the only way
back is EDL -- possibly needing an EDL cable or test points.

Nothing here is required for root. Root goes through ``boox root``, which never
touches these partitions. This exists because it was asked for, and it is gated
accordingly.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from boox.console import banner, confirm_phrase, info, step, warn
from boox.errors import SafetyError
from boox.imaging import bootimg
from boox.ops.context import Context
from boox.safety import preflight
from boox.safety.tiers import Tier, classify
from boox.safety.verify import Reference, verify_candidate
from boox.util import human_size, sha256_file, short

CONFIRM_PHRASE = "REPLACE MY BOOTLOADER"

WARNING = """\
This writes a bootloader that did not come from your device.

  - It cannot be verified against anything. The provenance check
    will fail, and you will acknowledge that failure by name.
  - If the ABL is wrong for this SoC, the device will not reach
    fastboot or recovery. EDL is the only way back, and you may
    need an EDL cable or the mainboard test points to get there.
  - Erasing devinfo resets device state. Expect a factory reset.
  - None of this is needed for root, Magisk, debloating or
    firewalling. If that is why you are here, stop and run
    'boox root' instead.

This command requires, and checks:
  - a verified backup from this session covering every partition
    it writes
  - decrypted stock firmware, as a second restore source
  - a full preflight pass, including the write round-trip
  - the exact confirmation phrase, typed"""


@dataclass
class UnlockPlan:
    abl_image: Path
    frp_image: Path | None
    erase_devinfo: bool
    slots: tuple[str, ...]


def _check_abl(path: Path) -> None:
    data = Path(path).read_bytes()
    kind = bootimg.detect_kind(data)
    if kind != "elf":
        raise SafetyError(
            f"{path.name} is not an ELF image (detected: {kind})",
            remedy=(
                "An ABL is an ELF binary. Whatever this file is, it is not a bootloader, "
                "and writing it would brick the device."
            ),
        )
    if len(data) < 64 * 1024:
        warn(f"{path.name} is only {human_size(len(data))}, which is small for an ABL")


def run(
    ctx: Context,
    plan: UnlockPlan,
    *,
    i_understand: bool = False,
    assume_yes: bool = False,
) -> None:
    """Write a foreign ABL, an FRP unlock blob, and optionally erase devinfo."""
    banner("Bootloader unlock", WARNING, style="danger")

    if not i_understand:
        raise SafetyError(
            "this command requires --i-understand",
            remedy="Read the warning above first. Nothing has been done.",
        )

    _check_abl(plan.abl_image)

    props = ctx.device_props(required=False)
    ctx.enter_edl()
    session = ctx.session()

    backup = ctx.latest_backup()
    if backup is None:
        raise SafetyError(
            "no backup is available",
            remedy="Run 'boox backup' first. This command will not run without one.",
        )
    backup.require_intact()
    session.require_same_device(backup.identity)

    required = [f"abl_{slot}" for slot in plan.slots]
    if plan.erase_devinfo:
        required.append("devinfo")
    if plan.frp_image is not None:
        required.append("frp")
    absent = [name for name in required if backup.image(name) is None]
    if absent:
        raise SafetyError(
            f"the backup does not contain: {', '.join(absent)}",
            remedy=(
                "Take a fresh backup that covers every partition this command writes. "
                "Without it there is nothing to roll back to."
            ),
        )

    golden = ctx.golden()
    if golden is None:
        raise SafetyError(
            "no decrypted stock firmware is available",
            remedy=(
                "Run 'boox firmware fetch'. For an operation this dangerous, one "
                "restore source is not enough."
            ),
        )

    result = preflight.run(
        session, ctx.profile, ctx.journal,
        adb_props=props, backup=backup, golden_available=True,
    )
    info(result.render())
    result.raise_if_failed()
    token = result.token
    assert token is not None

    digest = sha256_file(plan.abl_image)
    banner(
        "About to write",
        "\n".join(
            [f"  abl_{slot}  <- {plan.abl_image.name}  ({short(digest)})" for slot in plan.slots]
            + ([f"  frp       <- {plan.frp_image.name}"] if plan.frp_image else [])
            + (["  devinfo   <- ERASE"] if plan.erase_devinfo else [])
            + [f"\nBackup that will be rolled back to: {backup.root}"]
        ),
        style="danger",
    )
    if not confirm_phrase(
        "This is the last chance to stop.", CONFIRM_PHRASE, assume_yes=assume_yes
    ):
        raise SafetyError("not confirmed; nothing was written")

    token.expert_unlocked = True

    for slot in plan.slots:
        target = f"abl_{slot}"
        assert classify(target) is Tier.CATASTROPHIC
        report = verify_candidate(
            plan.abl_image.read_bytes(),
            target=target,
            table=session.table,
            references=[Reference(f"device backup {target}", backup.image(target).read_bytes())],
            require_root_patch=False,
            expect_identity=backup.identity,
            actual_identity=session.identity,
        )
        # The one thing that genuinely cannot pass: this bootloader is foreign by
        # design. Acknowledge that single check by name so it is recorded, rather
        # than weakening verification in general.
        report.override(
            "provenance",
            f"deliberately writing a foreign bootloader ({plan.abl_image.name}, "
            f"sha256 {short(digest)}) confirmed with the phrase '{CONFIRM_PHRASE}'",
        )
        info(report.render())
        step(f"writing {target}")
        session.write(
            target, plan.abl_image, token=token, report=report,
            backup=backup.image(target), tier_overrides=ctx.profile.tier_overrides,
        )

    if plan.frp_image is not None:
        report = verify_candidate(
            plan.frp_image.read_bytes(), target="frp", table=session.table,
            references=[Reference("device backup frp", backup.image("frp").read_bytes())],
        )
        report.override("provenance", "FRP unlock blob is generated, not derived from the device")
        session.write(
            "frp", plan.frp_image, token=token, report=report,
            backup=backup.image("frp"), tier_overrides=ctx.profile.tier_overrides,
        )

    if plan.erase_devinfo:
        step("erasing devinfo so the unlock state takes effect")
        session.erase(
            "devinfo", token=token, backup=backup.image("devinfo"),
            tier_overrides=ctx.profile.tier_overrides,
        )

    session.reset()
    banner(
        "Written",
        "The device is rebooting. If it does not reach fastboot or Android:\n"
        "  1. Do not panic and do not keep power-cycling it.\n"
        "  2. Get it into EDL (see 'boox rescue playbook').\n"
        f"  3. boox rescue restore --backup {backup.root} "
        f"--partition {' --partition '.join(f'abl_{s}' for s in plan.slots)}\n\n"
        "That restores the original bootloader byte for byte.",
        style="warn",
    )
