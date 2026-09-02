import pytest

from boox.errors import FirmwareError
from boox.firmware.payload import Payload
from boox.firmware.protobuf import ProtobufError, parse
from tests.support import (
    STOCK_RAMDISK_ENTRIES,
    build_boot_image,
    build_payload,
    build_vbmeta,
    make_ramdisk,
    pb_bytes,
    pb_varint,
)

BOOT = build_boot_image(b"KERNEL" * 900, make_ramdisk(STOCK_RAMDISK_ENTRIES), header_version=4)
VBMETA = build_vbmeta()


@pytest.fixture
def payload_file(tmp_path):
    blob = build_payload({
        "boot": (BOOT, "replace"),
        "vbmeta": (VBMETA, "xz"),
        "dtbo": (b"\x00" * 8192, "zero"),
        "init_boot": (b"INIT" * 500, "bz"),
    })
    path = tmp_path / "payload.bin"
    path.write_bytes(blob)
    return path


def test_lists_partitions(payload_file):
    payload = Payload(payload_file)
    assert payload.names() == ["boot", "dtbo", "init_boot", "vbmeta"]
    assert payload.require("boot").size == len(BOOT)


def test_extracts_replace(payload_file, tmp_path):
    out = Payload(payload_file).extract("boot", tmp_path / "boot.img")
    assert out.read_bytes() == BOOT


def test_extracts_xz_and_bz(payload_file, tmp_path):
    payload = Payload(payload_file)
    assert payload.extract("vbmeta", tmp_path / "vbmeta.img").read_bytes() == VBMETA
    assert payload.extract("init_boot", tmp_path / "init.img").read_bytes() == b"INIT" * 500


def test_extracts_zero(payload_file, tmp_path):
    out = Payload(payload_file).extract("dtbo", tmp_path / "dtbo.img")
    assert out.read_bytes() == b"\x00" * 8192


def test_hash_mismatch_is_caught(tmp_path):
    """A corrupt download must not become a trusted golden image."""
    blob = bytearray(build_payload({"boot": (BOOT, "replace")}))
    blob[-64] ^= 0xFF                      # flip a byte inside the image data
    path = tmp_path / "payload.bin"
    path.write_bytes(bytes(blob))
    with pytest.raises(FirmwareError, match="download is corrupt"):
        Payload(path).extract("boot", tmp_path / "boot.img")


def test_incremental_ota_is_rejected(tmp_path):
    path = tmp_path / "payload.bin"
    path.write_bytes(build_payload({"boot": (BOOT, "delta")}))
    payload = Payload(path)
    assert not payload.require("boot").is_full
    with pytest.raises(FirmwareError, match="incremental OTA"):
        payload.extract("boot", tmp_path / "boot.img")


def test_missing_partition_lists_alternatives(payload_file, tmp_path):
    with pytest.raises(FirmwareError, match="contains: boot, dtbo"):
        Payload(payload_file).extract("nope", tmp_path / "x.img")


def test_rejects_non_payload(tmp_path):
    path = tmp_path / "notpayload.bin"
    path.write_bytes(b"PK\x03\x04" + b"\x00" * 1000)
    with pytest.raises(FirmwareError, match="not an Android OTA payload"):
        Payload(path)


def test_protobuf_reader_basics():
    msg = parse(pb_varint(1, 300) + pb_bytes(2, b"hello") + pb_varint(1, 7))
    assert msg.integer(1) == 300
    assert msg.get_all(1) == [300, 7]
    assert msg.string(2) == "hello"


def test_protobuf_rejects_truncated():
    with pytest.raises(ProtobufError):
        parse(pb_bytes(2, b"hello")[:-2])
