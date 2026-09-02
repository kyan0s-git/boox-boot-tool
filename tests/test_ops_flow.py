"""End-to-end rooting flow, with both the device and adb simulated."""

from pathlib import Path

import pytest

from boox import profiles
from boox.errors import SafetyError, VerificationError
from boox.ops import root as root_ops
from boox.ops.context import Context, Workspace
from boox.transport.adb import DeviceProps
from boox.transport.mock import MockBackend
from boox.transport.proc import Result
from tests.support import (
    MAGISK_RAMDISK_ENTRIES,
    STOCK_RAMDISK_ENTRIES,
    build_boot_image,
    build_vbmeta,
    make_ramdisk,
)

KERNEL = b"GC7G2-KERNEL" * 400
STOCK_BOOT = build_boot_image(KERNEL, make_ramdisk(STOCK_RAMDISK_ENTRIES), header_version=2)
PATCHED_BOOT = build_boot_image(KERNEL, make_ramdisk(MAGISK_RAMDISK_ENTRIES), header_version=2)
FOREIGN_BOOT = build_boot_image(b"OTHER-DEVICE" * 400,
                                make_ramdisk(MAGISK_RAMDISK_ENTRIES), header_version=2)
# Kernel-only boot, as shipped on devices that keep the ramdisk in init_boot.
KERNEL_ONLY_BOOT = build_boot_image(KERNEL, b"", header_version=4)
STOCK_INIT = build_boot_image(b"", make_ramdisk(STOCK_RAMDISK_ENTRIES),
                              header_version=4, os_version_raw=0x1A2B3C)
PATCHED_INIT = build_boot_image(b"", make_ramdisk(MAGISK_RAMDISK_ENTRIES),
                                header_version=4, os_version_raw=0x1A2B3C)


class FakeAdb:
    """Enough adb to drive the flow, backed by a directory standing in for /sdcard."""

    def __init__(self, staging: Path, slot: str = "a"):
        self.staging = Path(staging)
        self.staging.mkdir(parents=True, exist_ok=True)
        self.slot = slot
        self.shell_log: list[str] = []
        self.rebooted_to_edl = 0
        self.rooted = False

    def props(self) -> DeviceProps:
        return DeviceProps(
            serial="mockserial", model="Go Color 7 Gen II", device="gocolor7_2",
            build_fingerprint="onyx/gocolor7_2/test:13/rel", android_version="13",
            slot_suffix=f"_{self.slot}", security_patch="2026-05-05",
        )

    def reboot_edl(self) -> None:
        self.rebooted_to_edl += 1

    def push(self, local: Path, remote: str) -> None:
        (self.staging / Path(remote).name).write_bytes(Path(local).read_bytes())

    def pull(self, remote: str, local: Path) -> None:
        Path(local).write_bytes((self.staging / Path(remote).name).read_bytes())

    def list_dir(self, remote: str) -> list[str]:
        return sorted(p.name for p in self.staging.iterdir())

    def shell(self, command: str, timeout: int = 120) -> Result:
        self.shell_log.append(command)
        return Result(["adb", "shell", command], 0, "Success", "")

    def is_rooted(self) -> bool:
        return self.rooted


def make_device(tmp_path, *, layout: str = "boot") -> MockBackend:
    dev = MockBackend(tmp_path / "device")
    for slot in ("a", "b"):
        if layout == "boot":
            dev.add_partition(f"boot_{slot}", STOCK_BOOT, size=len(STOCK_BOOT) + 65536)
        else:
            dev.add_partition(f"boot_{slot}", KERNEL_ONLY_BOOT,
                              size=len(KERNEL_ONLY_BOOT) + 65536)
            dev.add_partition(f"init_boot_{slot}", STOCK_INIT, size=len(STOCK_INIT) + 65536)
        dev.add_partition(f"vbmeta_{slot}", build_vbmeta(), size=65536)
    dev.add_partition("misc", b"\xa5" * 512, size=4096)
    return dev


@pytest.fixture
def env(tmp_path, monkeypatch):
    device = make_device(tmp_path)
    adb = FakeAdb(tmp_path / "sdcard")
    ctx = Context(workspace=Workspace(tmp_path / "ws"), profile=profiles.load("gocolor7_2"),
                  edl_settle_seconds=0)
    ctx.workspace.ensure()
    ctx._adb = adb
    ctx.attach_backend(device)
    # The device never actually leaves EDL here, so skip the reconnect wait.
    monkeypatch.setattr(root_ops, "_wait_for_adb", lambda *a, **k: None)
    return ctx, device, adb


def patch_in_magisk(adb: FakeAdb, blob: bytes, name: str = "magisk_patched-28000_abcde.img"):
    """Stand in for the user patching the staged image in the Magisk app."""
    (adb.staging / name).write_bytes(blob)


def test_prepare_picks_the_ramdisk_bearing_partition(env):
    ctx, device, adb = env
    plan = root_ops.prepare(ctx)
    assert plan.base == "boot"
    assert plan.partition == "boot_a"          # active slot, not both
    assert plan.slot == "a"
    # We stage the whole partition dump, so it is the image plus zero padding.
    staged = (adb.staging / Path(plan.device_path).name).read_bytes()
    assert staged.startswith(STOCK_BOOT)


def test_prepare_prefers_init_boot_when_that_holds_the_ramdisk(tmp_path, monkeypatch):
    device = make_device(tmp_path, layout="init_boot")
    adb = FakeAdb(tmp_path / "sdcard")
    ctx = Context(workspace=Workspace(tmp_path / "ws"), profile=profiles.load("gocolor7_2"),
                  edl_settle_seconds=0)
    ctx.workspace.ensure()
    ctx._adb = adb
    ctx.attach_backend(device)
    monkeypatch.setattr(root_ops, "_wait_for_adb", lambda *a, **k: None)

    plan = root_ops.prepare(ctx)
    assert plan.base == "init_boot"
    assert plan.partition == "init_boot_a"


def test_full_root_flow(env):
    ctx, device, adb = env
    root_ops.prepare(ctx)
    patch_in_magisk(adb, PATCHED_BOOT)

    root_ops.apply(ctx, allow_missing_golden=True)

    assert device.partition_bytes("boot_a").startswith(PATCHED_BOOT)
    # The inactive slot is deliberately left alone as a fallback.
    assert device.partition_bytes("boot_b").startswith(STOCK_BOOT)
    assert ctx.journal.is_clean()
    assert not (ctx.workspace.work / root_ops.STATE_FILE).exists()


def test_root_refuses_an_image_from_another_device(env):
    ctx, device, adb = env
    root_ops.prepare(ctx)
    patch_in_magisk(adb, FOREIGN_BOOT)

    with pytest.raises(VerificationError, match="nothing was written"):
        root_ops.apply(ctx, allow_missing_golden=True)
    assert device.partition_bytes("boot_a").startswith(STOCK_BOOT)


def test_root_refuses_an_unpatched_image(env):
    ctx, device, adb = env
    root_ops.prepare(ctx)
    patch_in_magisk(adb, STOCK_BOOT)

    with pytest.raises(VerificationError):
        root_ops.apply(ctx, allow_missing_golden=True)
    assert device.partition_bytes("boot_a").startswith(STOCK_BOOT)


def test_root_requires_golden_firmware_unless_waived(env):
    ctx, device, adb = env
    root_ops.prepare(ctx)
    patch_in_magisk(adb, PATCHED_BOOT)

    with pytest.raises(SafetyError, match="second restore source"):
        root_ops.apply(ctx)
    assert device.partition_bytes("boot_a").startswith(STOCK_BOOT)


def test_ambiguous_patched_images_are_refused(env):
    ctx, device, adb = env
    root_ops.prepare(ctx)
    patch_in_magisk(adb, PATCHED_BOOT, "magisk_patched-28000_aaaaa.img")
    patch_in_magisk(adb, FOREIGN_BOOT, "magisk_patched-28000_bbbbb.img")

    with pytest.raises(Exception, match="several patched images"):
        root_ops.apply(ctx, allow_missing_golden=True)
    assert device.partition_bytes("boot_a").startswith(STOCK_BOOT)


def test_apply_without_prepare_says_so(env):
    ctx, _, _ = env
    with pytest.raises(Exception, match="no prepared rooting session"):
        root_ops.apply(ctx, allow_missing_golden=True)


def test_both_slots_writes_the_inactive_slot_too(env):
    ctx, device, adb = env
    root_ops.prepare(ctx)
    patch_in_magisk(adb, PATCHED_BOOT)

    root_ops.apply(ctx, allow_missing_golden=True, both_slots=True)
    assert device.partition_bytes("boot_a").startswith(PATCHED_BOOT)
    assert device.partition_bytes("boot_b").startswith(PATCHED_BOOT)


def test_slot_b_device_writes_slot_b(tmp_path, monkeypatch):
    device = make_device(tmp_path)
    adb = FakeAdb(tmp_path / "sdcard", slot="b")
    ctx = Context(workspace=Workspace(tmp_path / "ws"), profile=profiles.load("gocolor7_2"),
                  edl_settle_seconds=0)
    ctx.workspace.ensure()
    ctx._adb = adb
    ctx.attach_backend(device)
    monkeypatch.setattr(root_ops, "_wait_for_adb", lambda *a, **k: None)

    plan = root_ops.prepare(ctx)
    assert plan.partition == "boot_b"
    patch_in_magisk(adb, PATCHED_BOOT)
    root_ops.apply(ctx, allow_missing_golden=True)
    assert device.partition_bytes("boot_b").startswith(PATCHED_BOOT)
    assert device.partition_bytes("boot_a").startswith(STOCK_BOOT)
