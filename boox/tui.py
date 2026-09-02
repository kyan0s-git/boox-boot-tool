"""The guided walkthrough.

The CLI lets you run the steps in any order; this runs them in the order that
is safe, shows what is already done, and refuses to offer a step whose
prerequisites are not met.  That ordering *is* the safety feature -- most ways
to get into trouble here involve doing the right things in the wrong sequence.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from boox.console import banner, console, info, ok, step, warn
from boox.errors import BooxError
from boox.ops import debloat as debloat_ops
from boox.ops import harden as harden_ops
from boox.ops import rescue as rescue_ops
from boox.ops import root as root_ops
from boox.ops.context import Context
from boox.safety.backup import create as create_backup

try:
    import questionary
except ImportError:  # pragma: no cover - questionary is a declared dependency
    questionary = None


@dataclass
class Stage:
    key: str
    title: str
    detail: str
    is_done: Callable[[Context], bool]
    can_run: Callable[[Context], str | None]   # returns a reason it cannot run, or None
    run: Callable[[Context], None]


# --------------------------------------------------------------------------- #
# stage implementations
# --------------------------------------------------------------------------- #

def _has_loader(ctx: Context) -> bool:
    return ctx.loader is not None and Path(ctx.loader).is_file()


def _stage_loader(ctx: Context) -> None:
    from boox.cli import cmd_loader_fetch

    class _Args:
        profile = ctx.profile.id
        workspace = str(ctx.workspace.root)
        loader = None
        backend = ctx.backend_name
        serial = ctx.adb_serial
        dry_run = ctx.dry_run
        dest = None
        force = False

    cmd_loader_fetch(_Args())
    info("Re-run the wizard with --loader pointing at the file you want to use.")


def _stage_firmware(ctx: Context) -> None:
    from boox.firmware.golden import acquire

    model = ctx.profile.onyx_model
    if not model:
        raise BooxError("this profile records no Onyx model name; fetch firmware manually")
    acquire(model, ctx.workspace.firmware)


def _stage_backup(ctx: Context) -> None:
    props = ctx.device_props(required=False)
    ctx.enter_edl()
    session = ctx.session()
    meta = {}
    if props:
        meta = {
            "model": props.model, "device": props.device,
            "fingerprint": props.build_fingerprint,
            "android_version": props.android_version,
            "security_patch": props.security_patch,
            "active_slot": props.active_slot, "serial": props.serial,
        }
    create_backup(session, ctx.profile, ctx.workspace.new_backup_dir(ctx.profile.id),
                  adb_props=meta)
    session.reset()


def _stage_root_prepare(ctx: Context) -> None:
    root_ops.prepare(ctx, skip_backup=True)


def _stage_root_apply(ctx: Context) -> None:
    root_ops.apply(ctx)


def _stage_debloat(ctx: Context) -> None:
    tiers = ["safe"]
    if questionary and questionary.confirm(
        "Also remove the aggressive tier (Onyx cloud, AI, app store, Play Store)?",
        default=False,
    ).ask():
        tiers.append("aggressive")
    debloat_ops.run(ctx.adb, tiers, dry_run=ctx.dry_run)


def _stage_harden(ctx: Context) -> None:
    harden_ops.apply_settings(ctx.adb, dry_run=ctx.dry_run)
    dest = ctx.workspace.root / "boox-blocklist.zip"
    harden_ops.build_hosts_module(dest)
    if ctx.adb.is_rooted():
        if questionary is None or questionary.confirm(
            "Install the blocklist module now?", default=True
        ).ask():
            harden_ops.install_module(ctx.adb, dest, dry_run=ctx.dry_run)
    else:
        warn("device is not rooted yet; install the module after rooting")
    banner("Firewall", harden_ops.firewall_guidance(), style="warn")


def _root_prepared(ctx: Context) -> bool:
    return (ctx.workspace.work / root_ops.STATE_FILE).is_file()


STAGES: list[Stage] = [
    Stage(
        key="loader",
        title="Get an EDL loader",
        detail="Without one the tool cannot talk to the device at all.",
        is_done=_has_loader,
        can_run=lambda ctx: None,
        run=_stage_loader,
    ),
    Stage(
        key="firmware",
        title="Fetch official firmware",
        detail="Gives the verifier a reference that did not come from your tablet.",
        is_done=lambda ctx: ctx.golden() is not None,
        can_run=lambda ctx: None,
        run=_stage_firmware,
    ),
    Stage(
        key="backup",
        title="Take a full verified backup",
        detail="Required before anything is written. Every partition read twice and hashed.",
        is_done=lambda ctx: ctx.latest_backup() is not None,
        can_run=lambda ctx: None if _has_loader(ctx) else "needs an EDL loader first",
        run=_stage_backup,
    ),
    Stage(
        key="root-prepare",
        title="Stage the boot image for Magisk",
        detail="Works out which partition and slot to patch, and puts the image on the device.",
        is_done=_root_prepared,
        can_run=lambda ctx: (
            None if _has_loader(ctx) and ctx.latest_backup() is not None
            else "needs a loader and a backup first"
        ),
        run=_stage_root_prepare,
    ),
    Stage(
        key="root-apply",
        title="Verify and write the patched image",
        detail="Refuses anything that cannot be traced back to your own stock image.",
        is_done=lambda ctx: False,
        can_run=lambda ctx: (
            None if _root_prepared(ctx) else "run the staging step first, then patch in Magisk"
        ),
        run=_stage_root_apply,
    ),
    Stage(
        key="debloat",
        title="Debloat",
        detail="Disables packages for the current user only. Fully reversible, no root needed.",
        is_done=lambda ctx: False,
        can_run=lambda ctx: None,
        run=_stage_debloat,
    ),
    Stage(
        key="harden",
        title="Harden the network",
        detail="Move NTP off Chinese servers and null-route Onyx telemetry.",
        is_done=lambda ctx: False,
        can_run=lambda ctx: None,
        run=_stage_harden,
    ),
]


# --------------------------------------------------------------------------- #
# driver
# --------------------------------------------------------------------------- #

def _status_line(ctx: Context, stage: Stage) -> str:
    if stage.is_done(ctx):
        return f"[ok]done[/ok]     {stage.title}"
    blocked = stage.can_run(ctx)
    if blocked:
        return f"[dim]blocked[/dim]  {stage.title}  [dim]({blocked})[/dim]"
    return f"[warn]ready[/warn]    {stage.title}"


def _overview(ctx: Context) -> None:
    console.print()
    console.print(f"[step]{ctx.profile.name}[/step]  workspace {ctx.workspace.root}")
    if ctx.dry_run:
        console.print("[warn]dry run: nothing will be written[/warn]")
    if not ctx.profile.verified:
        console.print(
            "[warn]this profile has not been confirmed on real hardware; "
            "preflight still measures your device before any write[/warn]"
        )
    console.print()
    for stage in STAGES:
        console.print("  " + _status_line(ctx, stage))
    console.print()


def run(ctx: Context) -> int:
    if questionary is None:
        console.print("[danger]questionary is not installed[/danger]")
        console.print("Install it with: pip install questionary")
        return 2

    banner(
        "boox-boot-tool",
        "This walks through rooting and hardening in the order that is safe.\n"
        "You can stop at any point; nothing is written until the very last step,\n"
        "and that step refuses anything it cannot verify.\n\n"
        "If the device is already in trouble, choose 'Recovery' below.",
        style="step",
    )

    while True:
        _overview(ctx)
        unfinished = ctx.journal.unfinished()
        if unfinished:
            warn(f"{len(unfinished)} interrupted operation(s) from a previous run:")
            for entry in unfinished:
                warn(f"  {entry.describe()}")

        choices = []
        for stage in STAGES:
            blocked = stage.can_run(ctx)
            label = stage.title + (f"   ({blocked})" if blocked else "")
            choices.append(questionary.Choice(label, value=stage.key, disabled=blocked))
        choices.append(questionary.Choice("Recovery: diagnose and restore", value="rescue"))
        choices.append(questionary.Choice("Quit", value="quit"))

        answer = questionary.select("What next?", choices=choices).ask()
        if answer in (None, "quit"):
            info("nothing further was done")
            return 0

        if answer == "rescue":
            rescue_ops.diagnose(ctx)
            rescue_ops.print_playbook()
            continue

        stage = next(s for s in STAGES if s.key == answer)
        console.print()
        step(stage.title)
        info(stage.detail)
        if not questionary.confirm("Continue?", default=True).ask():
            continue
        try:
            stage.run(ctx)
            ok(f"{stage.title}: finished")
        except BooxError as exc:
            console.print(f"[danger]{exc.message}[/danger]")
            if exc.remedy:
                console.print(f"[warn]{exc.remedy}[/warn]")
            info("Nothing further was written. You can pick another step or quit.")
