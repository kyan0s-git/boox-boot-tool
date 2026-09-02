"""adb wrapper.

Used for identifying the device, reading its build properties, moving boot
images on and off it, and asking it to drop into EDL.  adb is never a write
channel for partitions -- that is EDL's job.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from boox.errors import AdbError
from boox.transport.proc import Result, run, which

_DEVICE_LINE = re.compile(r"^(?P<serial>\S+)\s+(?P<state>device|unauthorized|offline)\b")


@dataclass(frozen=True)
class DeviceProps:
    serial: str
    model: str
    device: str
    build_fingerprint: str
    android_version: str
    slot_suffix: str
    security_patch: str

    @property
    def active_slot(self) -> str | None:
        """``_a`` -> ``a``. None when the device is not A/B."""
        s = self.slot_suffix.strip().lstrip("_")
        return s if s in ("a", "b") else None

    def describe(self) -> str:
        slot = f"slot {self.active_slot}" if self.active_slot else "not A/B"
        return (
            f"{self.model} ({self.device}), Android {self.android_version}, "
            f"{slot}, patch {self.security_patch}"
        )


class Adb:
    def __init__(self, binary: str | None = None, serial: str | None = None) -> None:
        self.binary = binary or which("adb")
        if not self.binary:
            raise AdbError(
                "adb was not found on PATH",
                remedy="Install Android platform-tools and make sure 'adb' is runnable.",
            )
        self.serial = serial

    def _argv(self, args: list[str]) -> list[str]:
        prefix = [self.binary]
        if self.serial:
            prefix += ["-s", self.serial]
        return prefix + args

    def _run(self, args: list[str], *, timeout: int = 120, echo: bool = True) -> Result:
        return run(self._argv(args), timeout=timeout, echo=echo)

    def devices(self) -> list[tuple[str, str]]:
        result = self._run(["devices"], timeout=30, echo=False)
        if not result.ok:
            raise AdbError(f"'adb devices' failed:\n{result.tail()}")
        out: list[tuple[str, str]] = []
        for line in result.stdout.splitlines()[1:]:
            m = _DEVICE_LINE.match(line.strip())
            if m:
                out.append((m.group("serial"), m.group("state")))
        return out

    def require_device(self) -> str:
        """Return the serial of the single connected, authorised device."""
        devices = self.devices()
        ready = [s for s, state in devices if state == "device"]
        if not ready:
            unauthorised = [s for s, state in devices if state == "unauthorized"]
            if unauthorised:
                raise AdbError(
                    "the device is connected but has not authorised this computer",
                    remedy="Unlock the tablet and accept the USB debugging prompt, then retry.",
                )
            raise AdbError(
                "no device visible to adb",
                remedy=(
                    "Enable Settings > More Settings > USB Debug Mode on the tablet, "
                    "reconnect the cable, and run 'adb devices' until it shows 'device'."
                ),
            )
        if len(ready) > 1 and not self.serial:
            raise AdbError(
                f"{len(ready)} devices are connected: {', '.join(ready)}",
                remedy="Disconnect the others, or pass --serial to pick one.",
            )
        return self.serial or ready[0]

    def getprop(self, name: str) -> str:
        result = self._run(["shell", "getprop", name], timeout=30, echo=False)
        if not result.ok:
            raise AdbError(f"getprop {name} failed:\n{result.tail()}")
        return result.stdout.strip()

    def props(self) -> DeviceProps:
        serial = self.require_device()
        get = self.getprop
        return DeviceProps(
            serial=serial,
            model=get("ro.product.model"),
            device=get("ro.product.device"),
            build_fingerprint=get("ro.build.fingerprint"),
            android_version=get("ro.build.version.release"),
            slot_suffix=get("ro.boot.slot_suffix"),
            security_patch=get("ro.build.version.security_patch"),
        )

    def shell(self, command: str, *, timeout: int = 120) -> Result:
        return self._run(["shell", command], timeout=timeout)

    def push(self, local: Path, remote: str) -> None:
        result = self._run(["push", str(local), remote], timeout=900)
        if not result.ok:
            raise AdbError(f"push of {local.name} failed:\n{result.tail()}")

    def pull(self, remote: str, local: Path) -> None:
        result = self._run(["pull", remote, str(local)], timeout=900)
        if not result.ok:
            raise AdbError(f"pull of {remote} failed:\n{result.tail()}")

    def list_dir(self, remote: str) -> list[str]:
        result = self._run(["shell", "ls", "-1", remote], timeout=60, echo=False)
        if not result.ok:
            return []
        return [line.strip() for line in result.stdout.splitlines() if line.strip()]

    def reboot_edl(self) -> None:
        """Ask the device to reboot into EDL (9008).

        adb returns immediately and the screen usually goes black or simply
        stops responding; that is the expected appearance of success.
        """
        result = self._run(["reboot", "edl"], timeout=60)
        if not result.ok and "closed" not in result.output.lower():
            raise AdbError(
                f"'adb reboot edl' failed:\n{result.tail()}",
                remedy="Some firmware needs 'adb reboot emergency' instead.",
            )

    def is_rooted(self) -> bool:
        result = self._run(["shell", "which", "su"], timeout=30, echo=False)
        return result.ok and "/su" in result.stdout
