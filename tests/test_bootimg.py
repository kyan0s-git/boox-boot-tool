import struct

import pytest

from boox.errors import ImageError
from boox.imaging import bootimg
from tests.support import build_boot_image, make_ramdisk, STOCK_RAMDISK_ENTRIES

KERNEL = b"KERNELBYTES" * 500


@pytest.mark.parametrize("version", [0, 1, 2, 3, 4])
def test_roundtrip_all_header_versions(version):
    ramdisk = make_ramdisk(STOCK_RAMDISK_ENTRIES)
    img = build_boot_image(KERNEL, ramdisk, header_version=version)
    parsed = bootimg.parse(img)
    assert parsed.kind == "boot"
    assert parsed.header_version == version
    assert parsed.kernel == KERNEL
    assert parsed.ramdisk == ramdisk


def test_page_size_2048_v0():
    ramdisk = make_ramdisk(STOCK_RAMDISK_ENTRIES)
    img = build_boot_image(KERNEL, ramdisk, header_version=0, page_size=2048)
    parsed = bootimg.parse(img)
    assert parsed.page_size == 2048
    assert parsed.kernel == KERNEL


def test_trailing_partition_padding_is_tolerated():
    """A partition read returns the whole partition, zero-padded. Must still parse."""
    ramdisk = make_ramdisk(STOCK_RAMDISK_ENTRIES)
    img = build_boot_image(KERNEL, ramdisk, header_version=2, pad_to=64 * 1024 * 1024)
    parsed = bootimg.parse(img)
    assert parsed.kernel == KERNEL
    assert parsed.payload_end < len(img)


def test_detect_kind():
    assert bootimg.detect_kind(b"ANDROID!" + b"\x00" * 100) == "boot"
    assert bootimg.detect_kind(b"VNDRBOOT" + b"\x00" * 100) == "vendor_boot"
    assert bootimg.detect_kind(b"AVB0" + b"\x00" * 100) == "vbmeta"
    assert bootimg.detect_kind(b"\x7fELF" + b"\x00" * 100) == "elf"
    assert bootimg.detect_kind(b"\x00" * 100) == "empty"
    assert bootimg.detect_kind(b"garbage!" * 10) == "unknown"


def test_rejects_non_boot_image():
    with pytest.raises(ImageError, match="not an Android boot image"):
        bootimg.parse(b"\x00" * 8192)


def test_rejects_truncated_image():
    ramdisk = make_ramdisk(STOCK_RAMDISK_ENTRIES)
    img = build_boot_image(KERNEL, ramdisk, header_version=2)
    with pytest.raises(ImageError):
        bootimg.parse(img[: len(img) // 2])


def test_rejects_zero_length_kernel():
    img = bytearray(build_boot_image(KERNEL, make_ramdisk(["init"]), header_version=2))
    struct.pack_into("<I", img, 8, 0)
    with pytest.raises(ImageError, match="zero-length kernel"):
        bootimg.parse(bytes(img))


def test_rejects_implausible_page_size():
    img = bytearray(build_boot_image(KERNEL, make_ramdisk(["init"]), header_version=2))
    struct.pack_into("<I", img, 36, 12345)  # not a power of two
    with pytest.raises(ImageError, match="implausible page size"):
        bootimg.parse(bytes(img))


def test_rejects_unsupported_header_version():
    img = bytearray(build_boot_image(KERNEL, make_ramdisk(["init"]), header_version=2))
    struct.pack_into("<I", img, 40, 9)
    with pytest.raises(ImageError, match="unsupported boot header version"):
        bootimg.parse(bytes(img))


def test_oversized_section_is_rejected():
    """A header claiming more kernel than the file holds must not be trusted."""
    img = bytearray(build_boot_image(KERNEL, make_ramdisk(["init"]), header_version=2))
    struct.pack_into("<I", img, 8, len(img) * 4)
    with pytest.raises(ImageError, match="runs past the end"):
        bootimg.parse(bytes(img))


def test_os_version_decoding():
    # Android 13.0.0, 2024-05
    raw = ((13 << 14) | (0 << 7) | 0) << 11 | ((24 << 4) | 5)
    img = build_boot_image(KERNEL, make_ramdisk(["init"]), header_version=4, os_version_raw=raw)
    assert bootimg.parse(img).os_version == "13.0.0 / 2024-05"
