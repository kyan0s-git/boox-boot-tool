"""Debloating.

Two rules make this safe to run and safe to undo:

* only ``pm uninstall --user 0`` is ever used, which hides a package from the
  current user without touching the system partition. ``--restore`` brings any
  of it back with ``cmd package install-existing``.
* a protected list is enforced in code. On these devices the Onyx launcher is
  also the settings UI, so removing it leaves a tablet you cannot configure.

Nothing here needs root, and nothing here writes to a partition.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from importlib import resources
from pathlib import Path

from boox.console import banner, info, ok, step, warn
from boox.errors import BooxError
from boox.transport.adb import Adb

TIERS = ("safe", "aggressive")


def _read_list(name: str) -> list[tuple[str, str]]:
    """Return (package, trailing comment context) pairs, comments stripped."""
    text = resources.files("boox.data.debloat").joinpath(f"{name}.txt").read_text(encoding="utf-8")
    out: list[tuple[str, str]] = []
    note = ""
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped:
            note = ""
            continue
        if stripped.startswith("#"):
            note = (note + " " + stripped.lstrip("# ")).strip()
            continue
        out.append((stripped, note))
    return out


def packages(tier: str) -> list[str]:
    if tier not in TIERS:
        raise BooxError(f"unknown debloat tier {tier!r}", remedy=f"Choose one of: {', '.join(TIERS)}")
    return [pkg for pkg, _ in _read_list(tier)]


def protected() -> set[str]:
    return {pkg for pkg, _ in _read_list("protected")}


def annotations(tier: str) -> dict[str, str]:
    return {pkg: note for pkg, note in _read_list(tier)}


@dataclass
class DebloatResult:
    removed: list[str] = field(default_factory=list)
    already_gone: list[str] = field(default_factory=list)
    failed: list[tuple[str, str]] = field(default_factory=list)
    refused: list[str] = field(default_factory=list)

    def summary(self) -> str:
        return (
            f"{len(self.removed)} removed, {len(self.already_gone)} already absent, "
            f"{len(self.failed)} failed, {len(self.refused)} refused as protected"
        )


def installed(adb: Adb) -> set[str]:
    result = adb.shell("pm list packages", timeout=120)
    if not result.ok:
        raise BooxError(f"could not list packages:\n{result.tail()}")
    return {
        line.strip().removeprefix("package:")
        for line in result.stdout.splitlines()
        if line.strip().startswith("package:")
    }


def run(
    adb: Adb,
    tiers: list[str],
    *,
    dry_run: bool = False,
    extra: list[str] | None = None,
    keep: list[str] | None = None,
) -> DebloatResult:
    """Disable packages from the named tiers for the current user."""
    guard = protected()
    keep_set = set(keep or [])
    wanted: list[str] = []
    for tier in tiers:
        wanted.extend(packages(tier))
    wanted.extend(extra or [])

    present = installed(adb)
    result = DebloatResult()
    seen: set[str] = set()

    for pkg in wanted:
        if pkg in seen:
            continue
        seen.add(pkg)
        if pkg in guard:
            result.refused.append(pkg)
            warn(f"{pkg}: on the protected list, skipping")
            continue
        if pkg in keep_set:
            info(f"{pkg}: kept by request")
            continue
        if pkg not in present:
            result.already_gone.append(pkg)
            continue
        if dry_run:
            info(f"dry run: would disable {pkg}")
            result.removed.append(pkg)
            continue
        out = adb.shell(f"pm uninstall --user 0 {pkg}", timeout=60)
        if out.ok and "Success" in out.stdout:
            result.removed.append(pkg)
            ok(f"disabled {pkg}")
        else:
            result.failed.append((pkg, out.tail(3)))
            warn(f"{pkg}: {out.tail(1) or 'failed'}")

    step(f"debloat: {result.summary()}")
    if result.removed and not dry_run:
        banner(
            "Reversible",
            "Every package above was disabled for user 0 only, not deleted.\n"
            "Bring one back:   boox debloat --restore <package>\n"
            "Bring all back:   boox debloat --restore-all",
            style="ok",
        )
    return result


def restore(adb: Adb, packages_to_restore: list[str], *, dry_run: bool = False) -> DebloatResult:
    result = DebloatResult()
    for pkg in packages_to_restore:
        if dry_run:
            info(f"dry run: would restore {pkg}")
            result.removed.append(pkg)
            continue
        out = adb.shell(f"cmd package install-existing {pkg}", timeout=60)
        if out.ok and "installed for user" in out.stdout.lower():
            result.removed.append(pkg)
            ok(f"restored {pkg}")
        else:
            result.failed.append((pkg, out.tail(3)))
            warn(f"{pkg}: could not restore -- {out.tail(1)}")
    return result


def all_known_packages() -> list[str]:
    out: list[str] = []
    for tier in TIERS:
        out.extend(packages(tier))
    return sorted(set(out))


def describe_tier(tier: str) -> str:
    notes = annotations(tier)
    lines = []
    for pkg in packages(tier):
        note = notes.get(pkg, "")
        lines.append(f"  {pkg:<52} {note[:70]}")
    return "\n".join(lines)


def write_report(result: DebloatResult, path: Path) -> None:
    import json

    path.write_text(
        json.dumps(
            {
                "removed": result.removed,
                "already_gone": result.already_gone,
                "refused": result.refused,
                "failed": [{"package": p, "error": e} for p, e in result.failed],
            },
            indent=2,
        )
    )
