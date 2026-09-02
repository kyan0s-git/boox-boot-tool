"""Shared wiring for the commands.

One place that knows how to find the device, pick a profile, open an EDL
session, and locate the backup/firmware for this workspace, so no command has
to assemble that itself (and none can accidentally assemble it without the
safety pieces attached).
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from pathlib import Path

from boox import profiles
from boox.console import info, step, warn
from boox.errors import BooxError, ProfileError
from boox.firmware.golden import GoldenFirmware
from boox.profiles import Profile
from boox.safety.backup import Backup
from boox.safety.journal import Journal
from boox.safety.session import DeviceSession
from boox.safety.verify import Reference
from boox.transport.adb import Adb, DeviceProps
from boox.transport.edl import EdlBackend, EdlClientBackend, TemblastBackend

DEFAULT_WORKSPACE = Path.home() / ".local" / "share" / "boox-boot-tool"


@dataclass
class Workspace:
    """Where this tool keeps everything for one device."""

    root: Path

    def __post_init__(self) -> None:
        self.root = Path(self.root)

    @property
    def backups(self) -> Path:
        return self.root / "backups"

    @property
    def firmware(self) -> Path:
        return self.root / "firmware"

    @property
    def work(self) -> Path:
        return self.root / "work"

    @property
    def journal_path(self) -> Path:
        return self.root / "journal.jsonl"

    def new_backup_dir(self, profile_id: str) -> Path:
        return self.backups / f"{profile_id}-{time.strftime('%Y%m%d-%H%M%S')}"

    def ensure(self) -> None:
        for path in (self.root, self.backups, self.firmware, self.work):
            path.mkdir(parents=True, exist_ok=True)


@dataclass
class Context:
    workspace: Workspace
    profile: Profile
    dry_run: bool = False
    adb_serial: str | None = None
    loader: Path | None = None
    backend_name: str = "edlclient"
    # How long to wait after asking the device to enter EDL before talking to it.
    edl_settle_seconds: float = 5.0
    _adb: Adb | None = field(default=None, repr=False)
    _session: DeviceSession | None = field(default=None, repr=False)
    _backend: EdlBackend | None = field(default=None, repr=False)
    _props: DeviceProps | None = field(default=None, repr=False)

    # ---- adb ------------------------------------------------------------------

    @property
    def adb(self) -> Adb:
        if self._adb is None:
            self._adb = Adb(serial=self.adb_serial)
        return self._adb

    def device_props(self, *, required: bool = True) -> DeviceProps | None:
        """Read build properties over adb, or None if the device is not in Android."""
        if self._props is not None:
            return self._props
        try:
            self._props = self.adb.props()
            return self._props
        except BooxError as exc:
            if required:
                raise
            info(f"adb not usable right now ({exc.message})")
            return None

    def active_slot(self) -> str | None:
        props = self.device_props(required=False)
        return props.active_slot if props else None

    # ---- EDL ------------------------------------------------------------------

    @property
    def journal(self) -> Journal:
        return Journal(self.workspace.journal_path)

    def attach_backend(self, backend: EdlBackend) -> DeviceSession:
        """Use a caller-supplied backend (the mock, in tests)."""
        self._backend = backend
        self._session = DeviceSession(
            backend, self.workspace.work, self.journal,
            dry_run=self.dry_run, profile_id=self.profile.id,
        )
        return self._session

    def session(self) -> DeviceSession:
        if self._session is not None:
            return self._session
        if self.loader is None:
            raise BooxError(
                "no EDL loader was given",
                remedy=(
                    "Pass --loader <file>. Candidates for this profile:\n  "
                    + "\n  ".join(
                        f"{c.name}" + (f"  <{c.url}>" if c.url else "")
                        for c in self.profile.loaders
                    )
                ),
            )
        cls = TemblastBackend if self.backend_name == "temblast" else EdlClientBackend
        backend = cls(self.loader, memory=self.profile.memory)
        return self.attach_backend(backend)

    def enter_edl(self) -> None:
        """Put the device into EDL if it is currently in Android."""
        props = self.device_props(required=False)
        if props is None:
            info("device is not answering adb; assuming it is already in EDL")
            return
        step("rebooting the device into EDL (the screen going blank is normal)")
        if self.dry_run:
            info("dry run: not actually rebooting")
            return
        self.adb.reboot_edl()
        self._props = None
        if self.edl_settle_seconds:
            time.sleep(self.edl_settle_seconds)

    # ---- artefacts ------------------------------------------------------------

    def latest_backup(self) -> Backup | None:
        try:
            return Backup.latest(self.workspace.backups)
        except BooxError as exc:
            warn(f"could not load the most recent backup: {exc.message}")
            return None

    def golden(self) -> GoldenFirmware | None:
        path = self.workspace.firmware
        if not (path / "golden.json").is_file():
            return None
        try:
            return GoldenFirmware.load(path)
        except BooxError as exc:
            warn(f"stock firmware present but unusable: {exc.message}")
            return None

    def references(self, partition: str) -> list[Reference]:
        """Every trusted image a candidate for ``partition`` may derive from."""
        out: list[Reference] = []
        backup = self.latest_backup()
        if backup:
            ref = backup.reference(partition)
            if ref:
                out.append(ref)
        golden = self.golden()
        if golden:
            ref = golden.reference(partition)
            if ref:
                out.append(ref)
        return out


def build(
    profile_id: str | None,
    workspace_root: Path | None = None,
    **kwargs,
) -> Context:
    """Assemble a context, resolving the profile from adb when not named."""
    workspace = Workspace(workspace_root or DEFAULT_WORKSPACE)
    workspace.ensure()

    if profile_id:
        profile = profiles.load(profile_id)
    else:
        profile = _autodetect_profile()
    return Context(workspace=workspace, profile=profile, **kwargs)


def _autodetect_profile() -> Profile:
    try:
        model = Adb().getprop("ro.product.model")
    except BooxError as exc:
        raise ProfileError(
            "could not identify the device over adb, and no --profile was given",
            remedy=f"Pass --profile explicitly. ({exc.message})",
        ) from exc
    profile = profiles.match_adb_model(model)
    if profile is None:
        known = ", ".join(sorted(profiles.available()))
        raise ProfileError(
            f"no profile claims a device reporting itself as {model!r}",
            remedy=(
                f"Known profiles: {known}. Copy boox/profiles/_template.toml to add "
                "one, and read SAFETY.md before using it to write anything."
            ),
        )
    info(f"detected {profile.name} from ro.product.model={model!r}")
    return profile
