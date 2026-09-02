"""Command line entry point."""

from __future__ import annotations

import argparse
import sys
import urllib.request
from pathlib import Path

from boox import __version__, profiles
from boox.console import banner, console, err_console, info, ok, step, warn
from boox.errors import BooxError
from boox.ops import context as ctx_mod
from boox.ops import debloat as debloat_ops
from boox.ops import harden as harden_ops
from boox.ops import rescue as rescue_ops
from boox.ops import root as root_ops
from boox.ops import unlock as unlock_ops
from boox.safety import preflight
from boox.safety.backup import Backup, create as create_backup
from boox.safety.verify import verify_candidate
from boox.util import human_size, sha256_file, short

EPILOG = """\
Typical first run:

  boox doctor                     see what the tool can reach
  boox loader fetch               download an EDL loader for this model
  boox firmware fetch             get official firmware as a golden reference
  boox backup                     full verified backup (required before any write)
  boox root prepare               stage the stock image for Magisk to patch
  boox root apply                 verify what Magisk produced, then write it

If something goes wrong:  boox rescue playbook
"""


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #

def make_context(args) -> ctx_mod.Context:
    return ctx_mod.build(
        getattr(args, "profile", None),
        workspace_root=Path(args.workspace) if args.workspace else None,
        dry_run=args.dry_run,
        adb_serial=args.serial,
        loader=Path(args.loader) if args.loader else None,
        backend_name=args.backend,
    )


def _resolve_slot(ctx: ctx_mod.Context, args, session) -> str | None:
    if getattr(args, "slot", None):
        return args.slot
    slot = ctx.active_slot()
    if slot is None and session.table.is_ab():
        raise BooxError(
            "this device is A/B but the active slot could not be determined",
            remedy="Boot into Android so adb can read ro.boot.slot_suffix, or pass --slot.",
        )
    return slot


# --------------------------------------------------------------------------- #
# commands
# --------------------------------------------------------------------------- #

def cmd_doctor(args) -> int:
    ctx = make_context(args)
    step("environment")
    info(f"boox-boot-tool {__version__}, workspace {ctx.workspace.root}")
    info(f"profile: {ctx.profile.describe()}")
    if not ctx.profile.verified:
        warn(
            "this profile has not been confirmed against real hardware. Preflight "
            "measures the device itself, so writes are still gated on evidence, but "
            "read SAFETY.md before using it."
        )

    props = ctx.device_props(required=False)
    if props:
        ok(f"adb: {props.describe()}")
        ok(f"rooted: {'yes' if ctx.adb.is_rooted() else 'no'}")
    else:
        warn("adb: no device (it may be in EDL, or debugging may be off)")

    backup = ctx.latest_backup()
    info(f"backup: {backup.describe() if backup else 'none in this workspace'}")
    golden = ctx.golden()
    info(f"stock firmware: {golden.describe() if golden else 'not fetched'}")

    unfinished = ctx.journal.unfinished()
    if unfinished:
        warn(f"{len(unfinished)} interrupted operation(s) in the journal:")
        for entry in unfinished:
            warn(f"  {entry.describe()}")
        warn("Run 'boox rescue diagnose' before doing anything else.")
    else:
        ok("journal: clean")

    if not args.preflight:
        info("run with --preflight to also test the EDL read and write path")
        return 0

    ctx.enter_edl()
    session = ctx.session()
    result = preflight.run(
        session, ctx.profile, ctx.journal,
        adb_props=props, backup=backup, golden_available=golden is not None,
        prove_write=not args.read_only,
    )
    console.print(result.render())
    return 0 if result.ok else 1


def cmd_profile_list(args) -> int:
    for profile in profiles.load_all():
        console.print(f"  {profile.id:<16} {profile.describe()}")
    return 0


def cmd_profile_show(args) -> int:
    profile = profiles.load(args.id)
    console.print(f"[step]{profile.name}[/step] ({profile.id})")
    console.print(f"  SoC          {profile.soc}")
    console.print(f"  storage      {profile.memory}")
    console.print(f"  field-tested {'yes' if profile.verified else 'no'}")
    console.print(f"  onyx model   {profile.onyx_model}")
    console.print(f"  root targets {', '.join(profile.root_targets)}")
    console.print(f"  round-trip   {profile.roundtrip_partition}")
    console.print(f"  backup set   {len(profile.backup_set)} partitions")
    if profile.loaders:
        console.print("  loaders:")
        for candidate in profile.loaders:
            console.print(f"    - {candidate.name}")
            if candidate.notes:
                console.print(f"      {candidate.notes}")
            if candidate.url:
                console.print(f"      {candidate.url}")
    if profile.quirks:
        console.print("  quirks:")
        for key, value in profile.quirks.items():
            console.print(f"    {key} = {value}")
    if profile.notes:
        console.print(profile.notes)
    return 0


def cmd_loader_fetch(args) -> int:
    ctx = make_context(args)
    dest_dir = Path(args.dest) if args.dest else ctx.workspace.root / "loaders"
    dest_dir.mkdir(parents=True, exist_ok=True)
    downloaded = []
    for candidate in ctx.profile.loaders:
        if not candidate.url:
            info(f"{candidate.name}: no URL recorded, you will have to source this one yourself")
            continue
        dest = dest_dir / candidate.name
        if dest.is_file() and not args.force:
            info(f"{candidate.name}: already present")
            downloaded.append(dest)
            continue
        step(f"downloading {candidate.name}")
        try:
            with urllib.request.urlopen(candidate.url, timeout=120) as resp:  # noqa: S310
                dest.write_bytes(resp.read())
        except Exception as exc:
            warn(f"{candidate.name}: {exc}")
            continue
        digest = sha256_file(dest)
        if candidate.sha256 and digest.lower() != candidate.sha256.lower():
            dest.unlink(missing_ok=True)
            warn(f"{candidate.name}: sha256 {short(digest)} does not match the profile; discarded")
            continue
        ok(f"{dest}  {human_size(dest.stat().st_size)}  {short(digest)}")
        downloaded.append(dest)
    if not downloaded:
        err_console.print("[danger]no loader could be downloaded[/danger]")
        return 1
    info("Pass one with --loader. Preflight will tell you whether it actually works.")
    return 0


def cmd_backup(args) -> int:
    ctx = make_context(args)
    props = ctx.device_props(required=False)
    ctx.enter_edl()
    session = ctx.session()
    dest = Path(args.dest) if args.dest else ctx.workspace.new_backup_dir(ctx.profile.id)
    adb_meta = {}
    if props:
        adb_meta = {
            "model": props.model, "device": props.device,
            "fingerprint": props.build_fingerprint,
            "android_version": props.android_version,
            "security_patch": props.security_patch,
            "active_slot": props.active_slot, "serial": props.serial,
        }
    create_backup(
        session, ctx.profile, dest,
        partitions=args.partition or None, adb_props=adb_meta,
    )
    if args.reboot:
        session.reset()
    return 0


def cmd_firmware_fetch(args) -> int:
    from boox.firmware.golden import acquire

    ctx = make_context(args)
    model = args.model or ctx.profile.onyx_model
    if not model:
        raise BooxError(
            "this profile records no Onyx model name",
            remedy="Pass --model, matching a row in BooxKeys.csv.",
        )
    acquire(
        model, ctx.workspace.firmware,
        upx=Path(args.upx) if args.upx else None,
        key=args.key, iv=args.iv,
        keys_csv=Path(args.keys) if args.keys else None,
    )
    return 0


def cmd_firmware_keys(args) -> int:
    from boox.firmware import keys as keys_mod

    if args.fetch:
        dest = keys_mod.fetch(Path(args.dest) if args.dest else None)
        ok(f"key database saved to {dest}")
        info(
            "This data is maintained by the community at "
            "github.com/Hagb/decryptBooxUpdateUpx and is not redistributed with this tool."
        )
        return 0
    ctx = make_context(args)
    model = args.model or ctx.profile.onyx_model
    pair = keys_mod.find(model)
    console.print(f"{pair.model}: key {pair.key} iv {pair.iv}  (from {pair.source})")
    return 0


def cmd_firmware_show(args) -> int:
    ctx = make_context(args)
    golden = ctx.golden()
    if golden is None:
        warn("no stock firmware in this workspace; run 'boox firmware fetch'")
        return 1
    console.print(golden.describe())
    for name, entry in sorted(golden.images().items()):
        console.print(f"  {name:<16} {human_size(entry['size']):>10}  {short(entry['sha256'])}")
    problems = golden.verify()
    if problems:
        for problem in problems:
            warn(problem)
        return 1
    ok("all extracted images match their recorded hashes")
    return 0


def cmd_verify(args) -> int:
    ctx = make_context(args)
    image = Path(args.image)
    references = ctx.references(args.target)
    if not references:
        warn(
            f"no backup or stock image for {args.target} in this workspace, so provenance "
            "cannot be checked -- which is itself a reason not to write this."
        )
    report = verify_candidate(
        image.read_bytes(),
        target=args.target,
        table=None,
        references=references,
        require_root_patch=args.expect_root,
    )
    console.print(f"[step]{image.name}[/step] as {args.target}")
    console.print(report.render())
    if report.ok:
        ok("would be accepted for writing")
        return 0
    err_console.print("[danger]would be refused[/danger]")
    return 1


def cmd_root_prepare(args) -> int:
    ctx = make_context(args)
    root_ops.prepare(ctx, skip_backup=args.skip_backup)
    return 0


def cmd_root_apply(args) -> int:
    ctx = make_context(args)
    root_ops.apply(
        ctx,
        patched=Path(args.patched) if args.patched else None,
        allow_missing_golden=args.allow_missing_golden,
        both_slots=args.both_slots,
    )
    return 0


def cmd_unroot(args) -> int:
    ctx = make_context(args)
    ctx.enter_edl()
    session = ctx.session()
    slot = _resolve_slot(ctx, args, session)
    targets = args.partition or [
        name for base in ctx.profile.root_targets
        for name in ([f"{base}_{slot}"] if slot else [base])
        if name in session.table
    ]
    if not targets:
        raise BooxError("could not work out which partition to restore; pass --partition")
    rescue_ops.restore(ctx, targets, from_golden=args.from_golden)
    session.reset()
    return 0


def cmd_rescue_diagnose(args) -> int:
    ctx = make_context(args)
    result = rescue_ops.diagnose(ctx)
    banner("Diagnosis", f"tier {result.tier}\n" + "\n".join(result.notes or ["nothing outstanding"]),
           style="step" if result.tier == "T0" else "warn")
    if result.tier != "T0":
        rescue_ops.print_playbook()
    return 0


def cmd_rescue_restore(args) -> int:
    ctx = make_context(args)
    rescue_ops.restore(
        ctx, args.partition,
        backup_dir=Path(args.backup) if args.backup else None,
        from_golden=args.from_golden,
    )
    if args.reboot:
        ctx.session().reset()
    return 0


def cmd_rescue_playbook(args) -> int:
    rescue_ops.print_playbook()
    return 0


def cmd_debloat(args) -> int:
    ctx = make_context(args)
    if args.list:
        for tier in debloat_ops.TIERS:
            console.print(f"[step]{tier}[/step]")
            console.print(debloat_ops.describe_tier(tier))
        console.print("[step]protected (never removed)[/step]")
        for pkg in sorted(debloat_ops.protected()):
            console.print(f"  {pkg}")
        return 0

    adb = ctx.adb
    if args.restore:
        debloat_ops.restore(adb, args.restore, dry_run=ctx.dry_run)
        return 0
    if args.restore_all:
        debloat_ops.restore(adb, debloat_ops.all_known_packages(), dry_run=ctx.dry_run)
        return 0

    result = debloat_ops.run(
        adb, args.tier, dry_run=ctx.dry_run, extra=args.package, keep=args.keep
    )
    if args.report:
        debloat_ops.write_report(result, Path(args.report))
        info(f"report written to {args.report}")
    return 0 if not result.failed else 1


def cmd_harden(args) -> int:
    ctx = make_context(args)
    did_something = False

    if args.settings or args.all:
        harden_ops.apply_settings(ctx.adb, dry_run=ctx.dry_run)
        did_something = True

    if args.hosts or args.all:
        dest = Path(args.output) if args.output else ctx.workspace.root / "boox-blocklist.zip"
        harden_ops.build_hosts_module(dest, extra_domains=args.block)
        if args.install:
            harden_ops.install_module(ctx.adb, dest, dry_run=ctx.dry_run)
        else:
            info(f"install it from the Magisk app, or re-run with --install: {dest}")
        did_something = True

    if args.install_module:
        harden_ops.install_module(ctx.adb, Path(args.install_module), dry_run=ctx.dry_run)
        did_something = True

    if args.ams_fix:
        harden_ops.ams_fix_scaffold(ctx.adb, ctx.workspace.work / "ams-fix")
        did_something = True

    if not did_something:
        console.print(harden_ops.summary(len(harden_ops.blocklist_domains())))
        console.print()
        banner("Firewall", harden_ops.firewall_guidance(), style="warn")
        info("Choose what to apply: --settings, --hosts, --ams-fix, or --all")
    else:
        banner("Firewall", harden_ops.firewall_guidance(), style="warn")
    return 0


def cmd_unlock(args) -> int:
    ctx = make_context(args)
    plan = unlock_ops.UnlockPlan(
        abl_image=Path(args.abl),
        frp_image=Path(args.frp) if args.frp else None,
        erase_devinfo=args.erase_devinfo,
        slots=tuple(args.slot or ("a", "b")),
    )
    unlock_ops.run(ctx, plan, i_understand=args.i_understand, assume_yes=args.yes)
    return 0


def cmd_wizard(args) -> int:
    from boox import tui

    return tui.run(make_context(args))


# --------------------------------------------------------------------------- #
# parser
# --------------------------------------------------------------------------- #

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="boox",
        description="Brick-resistant rooting, backup and hardening for Onyx Boox tablets.",
        epilog=EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--version", action="version", version=f"boox-boot-tool {__version__}")
    parser.add_argument("--profile", help="device profile id (autodetected over adb if omitted)")
    parser.add_argument("--workspace", help="where backups, firmware and the journal live")
    parser.add_argument("--loader", help="EDL firehose loader file")
    parser.add_argument("--backend", default="edlclient", choices=["edlclient", "temblast"])
    parser.add_argument("--serial", help="adb serial, when more than one device is attached")
    parser.add_argument("--dry-run", action="store_true",
                        help="print what would happen; never write to the device")
    parser.add_argument("--debug", action="store_true", help="show full tracebacks")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("doctor", help="check the environment, device and journal")
    p.add_argument("--preflight", action="store_true", help="also test the EDL read/write path")
    p.add_argument("--read-only", action="store_true",
                   help="with --preflight, skip the write round-trip (issues no token)")
    p.set_defaults(func=cmd_doctor)

    p = sub.add_parser("profile", help="inspect device profiles")
    psub = p.add_subparsers(dest="profile_command", required=True)
    q = psub.add_parser("list"); q.set_defaults(func=cmd_profile_list)
    q = psub.add_parser("show"); q.add_argument("id"); q.set_defaults(func=cmd_profile_show)

    p = sub.add_parser("loader", help="obtain an EDL loader")
    lsub = p.add_subparsers(dest="loader_command", required=True)
    q = lsub.add_parser("fetch")
    q.add_argument("--dest"); q.add_argument("--force", action="store_true")
    q.set_defaults(func=cmd_loader_fetch)

    p = sub.add_parser("backup", help="full verified backup of the device")
    p.add_argument("--dest")
    p.add_argument("--partition", action="append", help="limit to these (repeatable)")
    p.add_argument("--reboot", action="store_true", help="leave EDL when finished")
    p.set_defaults(func=cmd_backup)

    p = sub.add_parser("firmware", help="official firmware as a golden reference")
    fsub = p.add_subparsers(dest="firmware_command", required=True)
    q = fsub.add_parser("fetch")
    q.add_argument("--model"); q.add_argument("--upx"); q.add_argument("--keys")
    q.add_argument("--key"); q.add_argument("--iv")
    q.set_defaults(func=cmd_firmware_fetch)
    q = fsub.add_parser("keys")
    q.add_argument("--fetch", action="store_true", help="download the community key database")
    q.add_argument("--dest"); q.add_argument("--model")
    q.set_defaults(func=cmd_firmware_keys)
    q = fsub.add_parser("show"); q.set_defaults(func=cmd_firmware_show)

    p = sub.add_parser("verify", help="run the verifier against an image without writing")
    p.add_argument("image")
    p.add_argument("--as", dest="target", required=True, help="target partition, slot included")
    p.add_argument("--expect-root", action="store_true", help="require a Magisk patch")
    p.set_defaults(func=cmd_verify)

    p = sub.add_parser("root", help="install Magisk")
    rsub = p.add_subparsers(dest="root_command", required=True)
    q = rsub.add_parser("prepare", help="back up and stage the stock image for Magisk")
    q.add_argument("--skip-backup", action="store_true", help="reuse the most recent backup")
    q.set_defaults(func=cmd_root_prepare)
    q = rsub.add_parser("apply", help="verify what Magisk produced, then write it")
    q.add_argument("--patched", help="use this file instead of pulling it from the device")
    q.add_argument("--allow-missing-golden", action="store_true",
                   help="proceed with only the device backup as a restore source")
    q.add_argument("--both-slots", action="store_true",
                   help="also write the inactive slot, giving up your stock fallback")
    q.set_defaults(func=cmd_root_apply)

    p = sub.add_parser("unroot", help="put the stock boot image back")
    p.add_argument("--partition", action="append")
    p.add_argument("--slot", choices=["a", "b"])
    p.add_argument("--from-golden", action="store_true", help="use stock firmware, not the backup")
    p.set_defaults(func=cmd_unroot)

    p = sub.add_parser("rescue", help="diagnose and recover a device in trouble")
    ssub = p.add_subparsers(dest="rescue_command", required=True)
    q = ssub.add_parser("diagnose"); q.set_defaults(func=cmd_rescue_diagnose)
    q = ssub.add_parser("restore")
    q.add_argument("--partition", action="append", required=True)
    q.add_argument("--backup"); q.add_argument("--from-golden", action="store_true")
    q.add_argument("--reboot", action="store_true")
    q.set_defaults(func=cmd_rescue_restore)
    q = ssub.add_parser("playbook"); q.set_defaults(func=cmd_rescue_playbook)

    p = sub.add_parser("debloat", help="disable packages for the current user (reversible)")
    p.add_argument("--tier", action="append", default=None, choices=list(debloat_ops.TIERS))
    p.add_argument("--package", action="append", help="also disable this package")
    p.add_argument("--keep", action="append", help="do not disable this package")
    p.add_argument("--restore", action="append", help="re-enable a package")
    p.add_argument("--restore-all", action="store_true")
    p.add_argument("--list", action="store_true", help="show the lists and exit")
    p.add_argument("--report", help="write a JSON report here")
    p.set_defaults(func=cmd_debloat)

    p = sub.add_parser("harden", help="cut off Onyx telemetry")
    p.add_argument("--all", action="store_true")
    p.add_argument("--settings", action="store_true", help="NTP and captive-portal endpoints")
    p.add_argument("--hosts", action="store_true", help="build the systemless hosts module")
    p.add_argument("--install", action="store_true", help="install the module it just built")
    p.add_argument("--install-module", help="install an existing Magisk module zip")
    p.add_argument("--ams-fix", action="store_true", help="scaffold the services.jar fix")
    p.add_argument("--block", action="append", help="additional domain to null-route")
    p.add_argument("--output", help="where to write the module zip")
    p.set_defaults(func=cmd_harden)

    p = sub.add_parser(
        "unlock-bootloader",
        help="write a foreign ABL to get a working fastboot (DANGEROUS, not needed for root)",
    )
    p.add_argument("--abl", required=True, help="the ABL image to write")
    p.add_argument("--frp", help="FRP unlock blob")
    p.add_argument("--erase-devinfo", action="store_true")
    p.add_argument("--slot", action="append", choices=["a", "b"])
    p.add_argument("--i-understand", action="store_true", required=False,
                   help="required; confirms you have read what this does")
    p.add_argument("--yes", action="store_true", help="skip the typed confirmation")
    p.set_defaults(func=cmd_unlock)

    p = sub.add_parser("wizard", help="guided, step-by-step walkthrough")
    p.set_defaults(func=cmd_wizard)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if getattr(args, "tier", None) is None and getattr(args, "command", "") == "debloat":
        args.tier = ["safe"]
    try:
        return args.func(args)
    except BooxError as exc:
        err_console.print(f"\n[danger]{exc.message}[/danger]")
        if exc.remedy:
            err_console.print(f"[warn]{exc.remedy}[/warn]")
        if args.debug:
            raise
        return 2
    except KeyboardInterrupt:
        err_console.print("\n[warn]interrupted; nothing further was written[/warn]")
        return 130


if __name__ == "__main__":
    sys.exit(main())
