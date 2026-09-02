"""End-to-end safety tests against the simulated device.

These exercise the paths that matter when something goes wrong: a flaky cable,
a write that silently lands wrong, a crash mid-write, and an operator pointing
the tool at the wrong image.
"""

import json

import pytest

from boox import profiles
from boox.errors import PreflightError, SafetyError, VerificationError
from boox.safety import backup as backup_mod
from boox.safety import preflight, verify
from boox.safety.journal import Journal
from boox.safety.session import DeviceSession, WriteToken
from boox.safety.tiers import Tier
from boox.transport.mock import FaultConfig, MockBackend
from tests.support import (
    MAGISK_RAMDISK_ENTRIES,
    STOCK_RAMDISK_ENTRIES,
    build_boot_image,
    build_vbmeta,
    make_ramdisk,
)

KERNEL = b"GOCOLOR7-GEN2-KERNEL" * 300
FOREIGN_KERNEL = b"A-COMPLETELY-DIFFERENT-BOOX" * 300

STOCK_BOOT = build_boot_image(KERNEL, make_ramdisk(STOCK_RAMDISK_ENTRIES), header_version=2)
PATCHED_BOOT = build_boot_image(KERNEL, make_ramdisk(MAGISK_RAMDISK_ENTRIES), header_version=2)
FOREIGN_BOOT = build_boot_image(FOREIGN_KERNEL, make_ramdisk(MAGISK_RAMDISK_ENTRIES),
                                header_version=2)


@pytest.fixture
def profile():
    return profiles.load("gocolor7_2")


@pytest.fixture
def device(tmp_path):
    dev = MockBackend(tmp_path / "device")
    for slot in ("a", "b"):
        dev.add_partition(f"boot_{slot}", STOCK_BOOT, size=len(STOCK_BOOT) + 65536)
        dev.add_partition(f"vbmeta_{slot}", build_vbmeta(), size=65536)
        dev.add_partition(f"abl_{slot}", b"\x7fELF" + b"\x11" * 2000, size=8192)
    dev.add_partition("misc", b"\xa5" * 512, size=4096)
    dev.add_partition("frp", b"\x00" * 512, size=4096)
    dev.add_partition("devinfo", b"DEVINFO", size=4096)
    dev.add_partition("persist", b"persistdata", size=65536)
    return dev


def make_session(device, tmp_path, *, dry_run=False):
    journal = Journal(tmp_path / "journal.jsonl")
    session = DeviceSession(device, tmp_path / "work", journal, dry_run=dry_run,
                            profile_id="gocolor7_2")
    return session, journal


def full_setup(device, tmp_path, profile):
    """Preflight + backup, the state every write is required to start from."""
    session, journal = make_session(device, tmp_path)
    bk = backup_mod.create(session, profile, tmp_path / "backup")
    result = preflight.run(session, profile, journal, backup=bk, golden_available=False)
    result.raise_if_failed()
    assert result.token is not None
    return session, journal, bk, result.token


# --- preflight ---------------------------------------------------------------

def test_preflight_issues_token_on_healthy_device(device, tmp_path, profile):
    session, journal = make_session(device, tmp_path)
    bk = backup_mod.create(session, profile, tmp_path / "backup")
    result = preflight.run(session, profile, journal, backup=bk)
    assert result.ok, result.render()
    assert result.token is not None
    assert result.token.write_roundtrip_proven
    # The round trip must genuinely leave misc unchanged.
    assert device.partition_bytes("misc")[:512] == b"\xa5" * 512


def test_preflight_refuses_token_on_flaky_cable(tmp_path, profile):
    device = MockBackend(tmp_path / "device", faults=FaultConfig(flaky_read={"misc"}))
    device.add_partition("boot_a", STOCK_BOOT, size=len(STOCK_BOOT) + 4096)
    device.add_partition("misc", b"\xa5" * 512, size=4096)
    session, journal = make_session(device, tmp_path)
    result = preflight.run(session, profile, journal)
    assert not result.ok
    assert result.token is None
    assert any(c.name == "read_roundtrip" and not c.passed for c in result.checks)
    with pytest.raises(PreflightError, match="no write will be permitted"):
        result.raise_if_failed()


def test_preflight_refuses_token_when_writes_do_not_land(tmp_path, profile):
    device = MockBackend(tmp_path / "device", faults=FaultConfig(silent_corrupt={"misc"}))
    device.add_partition("boot_a", STOCK_BOOT, size=len(STOCK_BOOT) + 4096)
    device.add_partition("misc", b"\xa5" * 512, size=4096)
    session, journal = make_session(device, tmp_path)
    result = preflight.run(session, profile, journal)
    assert not result.ok
    assert result.token is None
    detail = next(c.detail for c in result.checks if c.name == "write_roundtrip")
    assert "not landing correctly" in detail


def test_preflight_flags_unfinished_journal(device, tmp_path, profile):
    session, journal = make_session(device, tmp_path)
    journal.begin("write", "boot_a", source="something.img")
    result = preflight.run(session, profile, journal)
    assert not result.ok
    assert any(c.name == "journal_clean" and not c.passed for c in result.checks)


def test_preflight_dry_run_issues_no_token(device, tmp_path, profile):
    session, journal = make_session(device, tmp_path, dry_run=True)
    result = preflight.run(session, profile, journal)
    assert result.token is None


# --- backup ------------------------------------------------------------------

def test_backup_captures_and_verifies(device, tmp_path, profile):
    session, _ = make_session(device, tmp_path)
    bk = backup_mod.create(session, profile, tmp_path / "backup")
    assert bk.verify() == []
    assert "boot_a" in bk.partitions()
    assert bk.identity.hwid == device.identity_value.hwid
    # Partitions the profile lists but this device lacks are skipped, not fatal.
    assert "modemst1" not in bk.partitions()


def test_backup_detects_tampering(device, tmp_path, profile):
    session, _ = make_session(device, tmp_path)
    bk = backup_mod.create(session, profile, tmp_path / "backup")
    (bk.root / "boot_a.img").write_bytes(b"corrupted")
    reloaded = backup_mod.Backup.load(bk.root)
    assert reloaded.verify()
    with pytest.raises(Exception, match="does not match its own manifest"):
        reloaded.require_intact()


def test_backup_refuses_when_no_wanted_partition_exists(tmp_path, profile):
    device = MockBackend(tmp_path / "empty")
    device.add_partition("something_else", b"x" * 64, size=4096)
    session, _ = make_session(device, tmp_path)
    with pytest.raises(Exception, match="none of the partitions"):
        backup_mod.create(session, profile, tmp_path / "backup")


# --- writes ------------------------------------------------------------------

def _report_for(session, bk, target, blob, *, require_patch=True):
    return verify.verify_candidate(
        blob, target=target, table=session.table,
        references=[bk.reference(target)] if bk.reference(target) else [],
        require_root_patch=require_patch,
        expect_identity=bk.identity, actual_identity=session.identity,
    )


def test_write_patched_boot_succeeds(device, tmp_path, profile):
    session, journal, bk, token = full_setup(device, tmp_path, profile)
    patched = tmp_path / "patched.img"
    patched.write_bytes(PATCHED_BOOT)
    report = _report_for(session, bk, "boot_a", PATCHED_BOOT)
    assert report.ok, report.render()

    session.write("boot_a", patched, token=token, report=report, backup=bk.image("boot_a"))
    assert device.partition_bytes("boot_a").startswith(PATCHED_BOOT)
    assert journal.is_clean()
    assert [e.state for e in journal.entries() if e.partition == "boot_a"] == ["done"]


def test_write_of_foreign_image_is_refused(device, tmp_path, profile):
    session, _, bk, token = full_setup(device, tmp_path, profile)
    foreign = tmp_path / "foreign.img"
    foreign.write_bytes(FOREIGN_BOOT)
    report = _report_for(session, bk, "boot_a", FOREIGN_BOOT)
    with pytest.raises(VerificationError, match="nothing was written"):
        session.write("boot_a", foreign, token=token, report=report, backup=bk.image("boot_a"))
    assert device.partition_bytes("boot_a").startswith(STOCK_BOOT)


def test_write_without_backup_is_refused(device, tmp_path, profile):
    session, _, bk, token = full_setup(device, tmp_path, profile)
    patched = tmp_path / "patched.img"
    patched.write_bytes(PATCHED_BOOT)
    report = _report_for(session, bk, "boot_a", PATCHED_BOOT)
    with pytest.raises(SafetyError, match="no backup of boot_a"):
        session.write("boot_a", patched, token=token, report=report, backup=None)


def test_preflight_issues_no_token_without_a_backup(device, tmp_path, profile):
    """Backup and golden firmware are the two restore sources; no backup, no token."""
    session, journal = make_session(device, tmp_path)
    result = preflight.run(session, profile, journal)          # no backup passed
    assert result.token is None
    assert any(c.name == "backup_available" and not c.passed for c in result.checks)


def test_write_refused_when_token_lacks_a_backup(device, tmp_path, profile):
    """The token guard holds even if a token is somehow obtained another way."""
    session, journal = make_session(device, tmp_path)
    bk = backup_mod.create(session, profile, tmp_path / "backup")
    token = WriteToken(
        profile_id=profile.id, identity=device.identity_value,
        read_roundtrip_proven=True, write_roundtrip_proven=True, backup_taken=False,
    )
    patched = tmp_path / "p.img"
    patched.write_bytes(PATCHED_BOOT)
    report = _report_for(session, bk, "boot_a", PATCHED_BOOT)
    with pytest.raises(SafetyError, match="no verified backup"):
        session.write("boot_a", patched, token=token, report=report, backup=bk.image("boot_a"))


def test_expired_token_is_refused(device, tmp_path, profile):
    session, journal, bk, token = full_setup(device, tmp_path, profile)
    token.issued_at -= 2 * 60 * 60
    patched = tmp_path / "p.img"
    patched.write_bytes(PATCHED_BOOT)
    report = _report_for(session, bk, "boot_a", PATCHED_BOOT)
    with pytest.raises(SafetyError, match="expired"):
        session.write("boot_a", patched, token=token, report=report, backup=bk.image("boot_a"))


def test_report_targeting_a_different_partition_is_refused(device, tmp_path, profile):
    session, _, bk, token = full_setup(device, tmp_path, profile)
    patched = tmp_path / "patched.img"
    patched.write_bytes(PATCHED_BOOT)
    report = _report_for(session, bk, "boot_a", PATCHED_BOOT)
    with pytest.raises(SafetyError, match="report is for"):
        session.write("boot_b", patched, token=token, report=report, backup=bk.image("boot_b"))


def test_catastrophic_partition_needs_the_expert_gate(device, tmp_path, profile):
    session, _, bk, token = full_setup(device, tmp_path, profile)
    abl = tmp_path / "abl.img"
    abl.write_bytes(device.partition_bytes("abl_a")[:8192])
    report = _report_for(session, bk, "abl_a", abl.read_bytes(), require_patch=False)
    with pytest.raises(SafetyError, match="expert gate is not unlocked"):
        session.write("abl_a", abl, token=token, report=report, backup=bk.image("abl_a"))

    token.expert_unlocked = True
    session.write("abl_a", abl, token=token, report=report, backup=bk.image("abl_a"))


def test_silent_corruption_is_caught_and_rolled_back(tmp_path, profile):
    device = MockBackend(tmp_path / "device")
    device.add_partition("boot_a", STOCK_BOOT, size=len(STOCK_BOOT) + 65536)
    device.add_partition("misc", b"\xa5" * 512, size=4096)
    session, journal, bk, token = full_setup(device, tmp_path, profile)

    # Corrupt only the next write, so preflight passes and the rollback succeeds.
    device.faults.silent_corrupt_once = {"boot_a"}
    patched = tmp_path / "patched.img"
    patched.write_bytes(PATCHED_BOOT)
    report = _report_for(session, bk, "boot_a", PATCHED_BOOT)

    with pytest.raises(SafetyError, match="read-back mismatch"):
        session.write("boot_a", patched, token=token, report=report, backup=bk.image("boot_a"))

    entry = [e for e in journal.entries() if e.partition == "boot_a"][-1]
    assert entry.state == "rolled_back"
    assert device.partition_bytes("boot_a").startswith(STOCK_BOOT)


def test_persistent_corruption_escalates_instead_of_pretending(tmp_path, profile):
    """If the rollback cannot verify either, say so loudly and name the rescue command."""
    device = MockBackend(tmp_path / "device")
    device.add_partition("boot_a", STOCK_BOOT, size=len(STOCK_BOOT) + 65536)
    device.add_partition("misc", b"\xa5" * 512, size=4096)
    session, journal, bk, token = full_setup(device, tmp_path, profile)

    device.faults.silent_corrupt = {"boot_a"}
    patched = tmp_path / "patched.img"
    patched.write_bytes(PATCHED_BOOT)
    report = _report_for(session, bk, "boot_a", PATCHED_BOOT)
    with pytest.raises(SafetyError, match="rollback did not verify") as exc:
        session.write("boot_a", patched, token=token, report=report, backup=bk.image("boot_a"))
    assert "boox rescue" in str(exc.value)
    assert "Do NOT reboot" in str(exc.value)


def test_crash_mid_write_leaves_a_recoverable_journal(tmp_path, profile):
    device = MockBackend(tmp_path / "device",
                         faults=FaultConfig(die_after_write="boot_a"))
    device.add_partition("boot_a", STOCK_BOOT, size=len(STOCK_BOOT) + 65536)
    device.add_partition("misc", b"\xa5" * 512, size=4096)
    session, journal, bk, token = full_setup(device, tmp_path, profile)

    patched = tmp_path / "patched.img"
    patched.write_bytes(PATCHED_BOOT)
    report = _report_for(session, bk, "boot_a", PATCHED_BOOT)
    with pytest.raises(Exception):
        session.write("boot_a", patched, token=token, report=report, backup=bk.image("boot_a"))

    # A later run must be able to see what was in flight and where its backup is.
    stale = journal.entries()[-1]
    assert stale.partition == "boot_a"
    assert stale.state in ("intent", "failed")
    assert stale.fields["backup"].endswith("boot_a.img")


def test_dry_run_touches_nothing(device, tmp_path, profile):
    session, journal = make_session(device, tmp_path)
    bk = backup_mod.create(session, profile, tmp_path / "backup")
    before = device.partition_bytes("boot_a")

    dry_session, dry_journal = make_session(device, tmp_path / "dry", dry_run=True)
    result = preflight.run(dry_session, profile, dry_journal, backup=bk)
    assert result.token is None, "a dry run must never issue a write token"
    token = WriteToken(
        profile_id="gocolor7_2", identity=device.identity_value,
        read_roundtrip_proven=True, write_roundtrip_proven=True, backup_taken=True,
    )
    patched = tmp_path / "patched.img"
    patched.write_bytes(PATCHED_BOOT)
    report = _report_for(dry_session, bk, "boot_a", PATCHED_BOOT)
    dry_session.write("boot_a", patched, token=token, report=report, backup=bk.image("boot_a"))
    assert device.partition_bytes("boot_a") == before


# --- restore -----------------------------------------------------------------

def test_restore_puts_stock_back(device, tmp_path, profile):
    session, journal, bk, token = full_setup(device, tmp_path, profile)
    patched = tmp_path / "patched.img"
    patched.write_bytes(PATCHED_BOOT)
    report = _report_for(session, bk, "boot_a", PATCHED_BOOT)
    session.write("boot_a", patched, token=token, report=report, backup=bk.image("boot_a"))
    assert device.partition_bytes("boot_a").startswith(PATCHED_BOOT)

    backup_mod.restore(session, bk, token, ["boot_a"], profile=profile)
    assert device.partition_bytes("boot_a").startswith(STOCK_BOOT)


def test_restore_refuses_a_different_device(device, tmp_path, profile):
    session, journal, bk, token = full_setup(device, tmp_path, profile)
    manifest = json.loads((bk.root / "manifest.json").read_text())
    manifest["identity"]["serial"] = "deadbeef"
    (bk.root / "manifest.json").write_text(json.dumps(manifest))
    other = backup_mod.Backup.load(bk.root)
    with pytest.raises(SafetyError, match="not the device the backup came from"):
        backup_mod.restore(session, other, token, ["boot_a"], profile=profile)
