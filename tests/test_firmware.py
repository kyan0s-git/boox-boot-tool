"""End-to-end firmware pipeline: update.upx -> zip -> payload.bin -> stock images."""

import io
import zipfile

import pytest

from boox.errors import FirmwareError
from boox.firmware import keys as keys_mod
from boox.firmware.golden import GoldenFirmware, acquire
from boox.firmware.upx import UpxDecryptor
from tests.support import (
    STOCK_RAMDISK_ENTRIES,
    build_boot_image,
    build_payload,
    build_vbmeta,
    make_ramdisk,
)

KEY = "8B2A051FF85FFD266C3639F8AF47C6F8"
IV = "30A4B381DB0E88188A065AF1B1C78A61"

BOOT = build_boot_image(b"KERNEL" * 900, make_ramdisk(STOCK_RAMDISK_ENTRIES), header_version=4)
VBMETA = build_vbmeta()


def encrypt_upx(plain: bytes, key_hex: str = KEY, iv_hex: str = IV) -> bytes:
    """Mirror image of what the tool decrypts: AES-128-CFB with a 128-bit segment."""
    try:
        from Cryptodome.Cipher import AES
    except ImportError:
        AES = pytest.importorskip("Crypto.Cipher.AES", reason="needs pycryptodome")

    cipher = AES.new(bytes.fromhex(key_hex), AES.MODE_CFB,
                     iv=bytes.fromhex(iv_hex), segment_size=128)
    return cipher.encrypt(plain)


def make_update_zip() -> bytes:
    payload = build_payload({"boot": (BOOT, "replace"), "vbmeta": (VBMETA, "xz")})
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as archive:
        archive.writestr("payload.bin", payload)
        archive.writestr("payload_properties.txt", "FILE_HASH=deadbeef\n")
    return buf.getvalue()


@pytest.fixture
def upx_file(tmp_path):
    path = tmp_path / "update.upx"
    path.write_bytes(encrypt_upx(make_update_zip()))
    return path


@pytest.fixture
def keys_csv(tmp_path):
    path = tmp_path / "BooxKeys.csv"
    path.write_text(f"Name,Model,Key,IV\nGoColor7_2,GoColor7_2,{KEY},{IV}\n")
    return path


def test_decrypt_roundtrip(upx_file, tmp_path):
    out = UpxDecryptor(KEY, IV).decrypt(upx_file, tmp_path / "update.zip")
    assert zipfile.ZipFile(out).namelist() == ["payload.bin", "payload_properties.txt"]


def test_wrong_key_is_rejected_immediately(upx_file, tmp_path):
    wrong = "00" * 16
    with pytest.raises(FirmwareError, match="not a zip archive"):
        UpxDecryptor(wrong, IV).decrypt(upx_file, tmp_path / "bad.zip")
    # And it must not leave a plausible-looking partial file behind.
    assert not (tmp_path / "bad.zip").exists()


def test_full_pipeline(upx_file, keys_csv, tmp_path):
    golden = acquire("GoColor7_2", tmp_path / "golden", upx=upx_file,
                     keys_csv=keys_csv, version="4.2-test")
    assert golden.verify() == []
    assert set(golden.images()) == {"boot", "vbmeta"}
    assert golden.image("boot").read_bytes() == BOOT
    # Slot suffixes resolve to the payload's unslotted names.
    assert golden.image("boot_a").read_bytes() == BOOT
    ref = golden.reference("boot_b")
    assert ref is not None and "stock firmware boot.img" in ref.label


def test_golden_reloads_from_disk(upx_file, keys_csv, tmp_path):
    acquire("GoColor7_2", tmp_path / "golden", upx=upx_file, keys_csv=keys_csv)
    reloaded = GoldenFirmware.load(tmp_path / "golden")
    assert "boot" in reloaded.images()
    assert reloaded.verify() == []


def test_golden_detects_tampered_image(upx_file, keys_csv, tmp_path):
    golden = acquire("GoColor7_2", tmp_path / "golden", upx=upx_file, keys_csv=keys_csv)
    (golden.root / "images" / "boot.img").write_bytes(b"tampered")
    assert golden.verify()


def test_missing_key_explains_how_to_get_one(upx_file, tmp_path):
    with pytest.raises(FirmwareError, match="boox firmware keys --fetch"):
        acquire("NoSuchModel", tmp_path / "golden", upx=upx_file,
                keys_csv=tmp_path / "absent.csv")


def test_zip_without_payload_is_explained(tmp_path, keys_csv):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as archive:
        archive.writestr("boot.img", BOOT)
    upx = tmp_path / "old.upx"
    upx.write_bytes(encrypt_upx(buf.getvalue()))
    with pytest.raises(FirmwareError, match="no payload.bin"):
        acquire("GoColor7_2", tmp_path / "golden", upx=upx, keys_csv=keys_csv)


def test_key_lookup_matches_name_or_model(keys_csv):
    assert keys_mod.find("GoColor7_2", csv_path=keys_csv).key == KEY
    assert keys_mod.find("gocolor7_2", csv_path=keys_csv).iv == IV
