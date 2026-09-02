"""Tests for the image verifier.

The two named scenarios below are the documented ways people have bricked these
tablets. If either of them ever stops failing verification, that is a serious
regression, not a flaky test.
"""

import pytest

from boox.errors import VerificationError
from boox.imaging.gpt import parse_gpt_binary
from boox.safety import verify
from boox.transport.sahara import DeviceIdentity
from tests.support import (
    MAGISK_RAMDISK_ENTRIES,
    STOCK_RAMDISK_ENTRIES,
    build_boot_image,
    build_gpt,
    build_vbmeta,
    make_ramdisk,
)

OUR_KERNEL = b"OUR-DEVICE-KERNEL" * 400
FOREIGN_KERNEL = b"SOME-OTHER-BOOX-KERNEL" * 400

PARTS = [
    ("boot_a", 100, 8192), ("boot_b", 8292, 8192),
    ("init_boot_a", 16484, 256), ("init_boot_b", 16740, 256),
    ("vbmeta_a", 17000, 16), ("misc", 17020, 8),
]
TABLE = parse_gpt_binary(build_gpt(PARTS))

STOCK_BOOT = build_boot_image(OUR_KERNEL, make_ramdisk(STOCK_RAMDISK_ENTRIES), header_version=2)
PATCHED_BOOT = build_boot_image(OUR_KERNEL, make_ramdisk(MAGISK_RAMDISK_ENTRIES), header_version=2)
FOREIGN_BOOT = build_boot_image(FOREIGN_KERNEL, make_ramdisk(MAGISK_RAMDISK_ENTRIES), header_version=2)

REFS = [verify.Reference("device backup boot_a", STOCK_BOOT)]


def check(report, name):
    return next(c for c in report.checks if c.name == name)


def test_properly_patched_image_passes():
    report = verify.verify_candidate(
        PATCHED_BOOT, target="boot_a", table=TABLE, references=REFS, require_root_patch=True
    )
    assert report.ok, report.render()
    assert check(report, "provenance").passed
    assert check(report, "root_patch_present").passed


def test_image_from_another_device_is_rejected():
    """The documented brick: writing another model's boot image to boot_a."""
    report = verify.verify_candidate(
        FOREIGN_BOOT, target="boot_a", table=TABLE, references=REFS, require_root_patch=True
    )
    assert not report.ok
    assert not check(report, "provenance").passed
    assert "does not match any trusted reference" in check(report, "provenance").detail
    with pytest.raises(VerificationError, match="nothing was written"):
        report.raise_if_failed()


def test_unpatched_image_rejected_when_root_expected():
    report = verify.verify_candidate(
        STOCK_BOOT, target="boot_a", table=TABLE, references=REFS, require_root_patch=True
    )
    assert not report.ok
    assert "never patched" in check(report, "root_patch_present").detail
    assert not check(report, "ramdisk_differs_from_stock").passed


def test_unpatched_image_accepted_when_restoring():
    """The same image is perfectly valid when we are restoring, not rooting."""
    report = verify.verify_candidate(
        STOCK_BOOT, target="boot_a", table=TABLE, references=REFS, require_root_patch=False
    )
    assert report.ok, report.render()


def test_oversized_image_rejected():
    big = PATCHED_BOOT + b"\x00" * (TABLE.require("boot_a").size_bytes + 1)
    report = verify.verify_candidate(big, target="boot_a", table=TABLE, references=REFS)
    assert not check(report, "fits_partition").passed


def test_wrong_format_for_target_rejected():
    report = verify.verify_candidate(
        build_vbmeta(), target="boot_a", table=TABLE, references=REFS
    )
    assert not report.ok
    assert not check(report, "magic_matches_target").passed


def test_boot_image_into_vbmeta_rejected():
    report = verify.verify_candidate(
        PATCHED_BOOT[:8192], target="vbmeta_a", table=TABLE,
        references=[verify.Reference("stock vbmeta", build_vbmeta())],
    )
    assert not check(report, "magic_matches_target").passed


def test_all_zero_image_rejected():
    report = verify.verify_candidate(b"\x00" * 4096, target="boot_a", table=TABLE, references=REFS)
    assert not check(report, "not_blank").passed


def test_truncated_image_rejected():
    report = verify.verify_candidate(
        PATCHED_BOOT[: len(PATCHED_BOOT) // 3], target="boot_a", table=TABLE, references=REFS
    )
    assert not report.ok
    assert not check(report, "header_parses").passed


def test_missing_partition_rejected():
    report = verify.verify_candidate(PATCHED_BOOT, target="boot_c", table=TABLE, references=REFS)
    assert not check(report, "partition_exists").passed


def test_no_reference_means_no_provenance():
    report = verify.verify_candidate(PATCHED_BOOT, target="boot_a", table=TABLE, references=[])
    assert not check(report, "provenance").passed
    assert "no trusted reference" in check(report, "provenance").detail


def test_device_binding_mismatch_rejected():
    backup_id = DeviceIdentity(hwid="0013f0e100000000", serial="aaaa1111")
    other_id = DeviceIdentity(hwid="0013f0e100000000", serial="bbbb2222")
    report = verify.verify_candidate(
        PATCHED_BOOT, target="boot_a", table=TABLE, references=REFS,
        expect_identity=backup_id, actual_identity=other_id,
    )
    assert not check(report, "device_binding").passed
    assert "serial" in check(report, "device_binding").detail


def test_device_binding_passes_for_same_device():
    ident = DeviceIdentity(hwid="0013f0e100000000", serial="aaaa1111")
    report = verify.verify_candidate(
        PATCHED_BOOT, target="boot_a", table=TABLE, references=REFS,
        expect_identity=ident, actual_identity=ident,
    )
    assert check(report, "device_binding").passed


# --- init_boot: kernel-less images need a different provenance anchor ---------

STOCK_INIT = build_boot_image(b"", make_ramdisk(STOCK_RAMDISK_ENTRIES),
                              header_version=4, os_version_raw=0x1A2B3C)
PATCHED_INIT = build_boot_image(b"", make_ramdisk(MAGISK_RAMDISK_ENTRIES),
                                header_version=4, os_version_raw=0x1A2B3C)
FOREIGN_INIT = build_boot_image(b"", make_ramdisk(MAGISK_RAMDISK_ENTRIES),
                                header_version=4, os_version_raw=0x995544)
INIT_REFS = [verify.Reference("device backup init_boot_a", STOCK_INIT)]


def test_patched_init_boot_passes():
    report = verify.verify_candidate(
        PATCHED_INIT, target="init_boot_a", table=TABLE,
        references=INIT_REFS, require_root_patch=True,
    )
    assert report.ok, report.render()
    assert "ramdisk entries are still present" in check(report, "provenance").detail


def test_init_boot_from_another_build_rejected():
    report = verify.verify_candidate(
        FOREIGN_INIT, target="init_boot_a", table=TABLE,
        references=INIT_REFS, require_root_patch=True,
    )
    assert not check(report, "provenance").passed


def test_kernel_bearing_image_into_init_boot_rejected():
    report = verify.verify_candidate(
        PATCHED_BOOT, target="init_boot_a", table=TABLE, references=INIT_REFS
    )
    assert not check(report, "provenance").passed


# --- property: no mutation of a good image may sneak through ------------------

def _mutations():
    yield "truncated", PATCHED_BOOT[:1000]
    yield "empty", b""
    yield "zeroed", b"\x00" * len(PATCHED_BOOT)
    yield "foreign_kernel", FOREIGN_BOOT
    yield "stock_not_patched", STOCK_BOOT
    yield "wrong_magic", b"NOTABOOT" + PATCHED_BOOT[8:]
    yield "byte_flipped_header", bytes([PATCHED_BOOT[0] ^ 0xFF]) + PATCHED_BOOT[1:]
    yield "vbmeta_instead", build_vbmeta()
    yield "random_garbage", bytes(range(256)) * 64


@pytest.mark.parametrize("label,blob", list(_mutations()), ids=lambda v: v if isinstance(v, str) else "")
def test_every_mutation_is_rejected(label, blob):
    report = verify.verify_candidate(
        blob, target="boot_a", table=TABLE, references=REFS, require_root_patch=True
    )
    assert not report.ok, f"{label} should not have verified:\n{report.render()}"
