"""CLI smoke tests. None of these touch a device."""

import pytest

from boox.cli import main
from tests.support import (
    MAGISK_RAMDISK_ENTRIES,
    STOCK_RAMDISK_ENTRIES,
    build_boot_image,
    make_ramdisk,
)


def run(argv, tmp_path, extra=()):
    return main(["--workspace", str(tmp_path), "--profile", "gocolor7_2", *extra, *argv])


def test_version(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["--version"])
    assert exc.value.code == 0
    assert "boox-boot-tool" in capsys.readouterr().out


def test_profile_list(tmp_path, capsys):
    assert run(["profile", "list"], tmp_path) == 0
    assert "gocolor7_2" in capsys.readouterr().out


def test_profile_show(tmp_path, capsys):
    assert run(["profile", "show", "gocolor7_2"], tmp_path) == 0
    out = capsys.readouterr().out
    assert "Go Color 7" in out
    assert "root targets" in out


def test_profile_show_unknown_is_explained(tmp_path, capsys):
    assert run(["profile", "show", "nope"], tmp_path) == 2
    assert "Known profiles" in capsys.readouterr().err


def test_debloat_list(tmp_path, capsys):
    assert run(["debloat", "--list"], tmp_path) == 0
    out = capsys.readouterr().out
    assert "com.onyx.aiassistant" in out
    assert "protected (never removed)" in out
    assert "com.onyx" in out


def test_rescue_playbook(tmp_path, capsys):
    assert run(["rescue", "playbook"], tmp_path) == 0
    out = capsys.readouterr().out
    assert "EDL" in out
    assert "microSD" in out


def test_harden_overview_mentions_the_ip_a_hosts_file_cannot_block(tmp_path, capsys):
    assert run(["harden"], tmp_path) == 0
    assert "119.23.143.188" in capsys.readouterr().out


def test_harden_builds_a_hosts_module(tmp_path):
    out = tmp_path / "block.zip"
    assert run(["harden", "--hosts", "--output", str(out)], tmp_path) == 0
    import zipfile

    with zipfile.ZipFile(out) as archive:
        hosts = archive.read("system/etc/hosts").decode()
    assert "0.0.0.0   send2boox.com" in hosts
    assert "0.0.0.0   onyx-international.cn" in hosts


def test_verify_refuses_without_a_reference(tmp_path, capsys):
    image = tmp_path / "patched.img"
    image.write_bytes(
        build_boot_image(b"K" * 4096, make_ramdisk(MAGISK_RAMDISK_ENTRIES), header_version=2)
    )
    code = run(["verify", str(image), "--as", "boot_a", "--expect-root"], tmp_path)
    assert code == 1
    out = capsys.readouterr()
    assert "provenance" in out.out
    assert "would be refused" in out.err


def test_verify_reports_a_stock_image_as_unpatched(tmp_path, capsys):
    image = tmp_path / "stock.img"
    image.write_bytes(
        build_boot_image(b"K" * 4096, make_ramdisk(STOCK_RAMDISK_ENTRIES), header_version=2)
    )
    assert run(["verify", str(image), "--as", "boot_a", "--expect-root"], tmp_path) == 1
    assert "never patched" in capsys.readouterr().out


def test_doctor_without_a_device_is_graceful(tmp_path, capsys):
    assert run(["doctor"], tmp_path) == 0
    out = capsys.readouterr().out
    assert "journal: clean" in out


def test_unlock_requires_the_understanding_flag(tmp_path, capsys):
    abl = tmp_path / "abl.img"
    abl.write_bytes(b"\x7fELF" + b"\x00" * 200000)
    assert run(["unlock-bootloader", "--abl", str(abl)], tmp_path) == 2
    err = capsys.readouterr().err
    assert "--i-understand" in err


def test_dry_run_flag_reaches_the_context(tmp_path, capsys):
    assert run(["doctor"], tmp_path, extra=["--dry-run"]) == 0
