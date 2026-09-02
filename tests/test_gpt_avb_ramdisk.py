import pytest

from boox.errors import ImageError
from boox.imaging import avb, gpt, ramdisk
from tests.support import (
    MAGISK_RAMDISK_ENTRIES,
    STOCK_RAMDISK_ENTRIES,
    build_gpt,
    build_vbmeta,
    make_ramdisk,
)

ENTRIES = [
    ("boot_a", 100, 200), ("boot_b", 300, 200),
    ("vbmeta_a", 500, 8), ("vbmeta_b", 508, 8),
    ("abl_a", 600, 16), ("abl_b", 616, 16),
    ("misc", 700, 2), ("persist", 800, 64),
]


def table():
    return gpt.parse_gpt_binary(build_gpt(ENTRIES))


def test_gpt_binary_parse():
    t = table()
    assert t.source == "gpt-binary"
    assert set(t.names()) == {n for n, _, _ in ENTRIES}
    assert t.require("boot_a").size_bytes == 200 * 512
    assert t.is_ab()


def test_slot_and_base_names():
    t = table()
    assert t.require("boot_a").base_name == "boot"
    assert t.require("boot_a").slot == "a"
    assert t.require("misc").slot is None
    assert t.require("misc").base_name == "misc"


def test_resolve_requires_explicit_slot():
    t = table()
    assert t.resolve("boot", "a").name == "boot_a"
    assert t.resolve("misc", None).name == "misc"
    with pytest.raises(ImageError, match="Refusing to guess"):
        t.resolve("boot", None)


def test_require_unknown_partition_lists_neighbours():
    t = table()
    with pytest.raises(ImageError, match="not in this device"):
        t.require("boot_c")


def test_gpt_rejects_garbage():
    with pytest.raises(ImageError, match="no GPT header"):
        gpt.parse_gpt_binary(b"\x00" * 8192)


def test_rawprogram_xml_parse():
    xml = """<?xml version="1.0"?><data>
      <program SECTOR_SIZE_IN_BYTES="512" file_sector_offset="0" filename="boot.img"
               label="boot_a" num_partition_sectors="131072" physical_partition_number="0"
               start_sector="262144"/>
      <program SECTOR_SIZE_IN_BYTES="512" filename="" label="misc"
               num_partition_sectors="2048" physical_partition_number="0" start_sector="1024"/>
    </data>"""
    t = gpt.parse_rawprogram_xml({"rawprogram0.xml": xml})
    assert t.require("boot_a").size_bytes == 131072 * 512
    assert t.require("misc").start_lba == 1024


def test_printgpt_text_parse():
    text = """
    Parsing Lun 0:
    boot_a          Offset 0x0000000020000000, Length 0x0000000004000000, Flags ...
    boot_b          Offset 0x0000000024000000, Length 0x0000000004000000, Flags ...
    misc            Offset 0x0000000001000000, Length 0x0000000000100000, Flags ...
    """
    t = gpt.parse_printgpt_text(text)
    assert set(t.names()) == {"boot_a", "boot_b", "misc"}
    assert t.require("boot_a").size_bytes == 0x4000000


def test_printgpt_text_rejects_unparseable():
    with pytest.raises(ImageError, match="could not parse"):
        gpt.parse_printgpt_text("nothing useful here\n")


def test_vbmeta_flags():
    enforced = avb.parse_vbmeta(build_vbmeta(flags=0))
    assert not enforced.verification_disabled
    assert enforced.signed
    assert "enforced" in enforced.describe()

    disabled = avb.parse_vbmeta(build_vbmeta(flags=avb.FLAG_VERIFICATION_DISABLED))
    assert disabled.verification_disabled
    assert "DISABLED" in disabled.describe()


def test_vbmeta_rejects_non_vbmeta():
    with pytest.raises(ImageError, match="not a vbmeta image"):
        avb.parse_vbmeta(b"ANDROID!" + b"\x00" * 512)


def test_ramdisk_detects_magisk():
    info = ramdisk.inspect(make_ramdisk(MAGISK_RAMDISK_ENTRIES))
    assert info.state is ramdisk.PatchState.PATCHED
    assert ".backup/.magisk" in info.evidence


def test_ramdisk_detects_stock():
    info = ramdisk.inspect(make_ramdisk(STOCK_RAMDISK_ENTRIES))
    assert info.state is ramdisk.PatchState.NOT_PATCHED
    assert "fstab.qcom" in info.entries


def test_ramdisk_uncompressed_cpio():
    info = ramdisk.inspect(make_ramdisk(MAGISK_RAMDISK_ENTRIES, codec="none"))
    assert info.compression == "none"
    assert info.patched


def test_ramdisk_unknown_codec_is_not_reported_as_stock():
    """An lz4/zstd ramdisk we cannot open must be UNKNOWN, never NOT_PATCHED."""
    fake_zstd = b"\x28\xb5\x2f\xfd" + b"\x99" * 512
    info = ramdisk.inspect(fake_zstd)
    assert info.state is ramdisk.PatchState.UNKNOWN
    assert info.compression == "zstd"


def test_ramdisk_empty():
    assert ramdisk.inspect(b"").state is ramdisk.PatchState.UNKNOWN


def test_ramdisk_corrupt_gzip_is_unknown():
    info = ramdisk.inspect(b"\x1f\x8b" + b"\x00" * 200)
    assert info.state is ramdisk.PatchState.UNKNOWN
