"""The guarded device session.

Backends move bytes; this decides whether they are allowed to.  Every write on
a real device goes through :meth:`DeviceSession.write`, which will not proceed
without all of:

* a write token issued by preflight (so the escape hatch was proven first),
* a verification report that passed, and
* a backup of the partition being overwritten.

After the write it reads the partition back and compares hashes.  If they
disagree the backup is restored immediately, before returning control, because
a partition that did not take the bytes we sent is exactly the state that turns
into a brick if the device reboots.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from pathlib import Path

from boox.console import info, ok, step, warn
from boox.errors import SafetyError
from boox.imaging.gpt import PartitionTable
from boox.safety.journal import Journal
from boox.safety.tiers import Tier, classify
from boox.safety.verify import Report
from boox.transport.edl import EdlBackend
from boox.transport.sahara import DeviceIdentity, mismatch
from boox.util import sha256_file, short

TOKEN_TTL_SECONDS = 60 * 60


@dataclass
class WriteToken:
    """Proof that preflight ran and passed on this device, in this process."""

    profile_id: str
    identity: DeviceIdentity
    issued_at: float = field(default_factory=time.time)
    read_roundtrip_proven: bool = False
    write_roundtrip_proven: bool = False
    backup_taken: bool = False
    golden_firmware_available: bool = False
    expert_unlocked: bool = False

    @property
    def expired(self) -> bool:
        return (time.time() - self.issued_at) > TOKEN_TTL_SECONDS

    def check_usable(self) -> None:
        if self.expired:
            raise SafetyError(
                "the preflight write token has expired",
                remedy="Re-run preflight so the device state is re-confirmed before writing.",
            )
        if not (self.read_roundtrip_proven and self.write_roundtrip_proven):
            raise SafetyError(
                "preflight did not prove the EDL read and write path",
                remedy="Run 'boox doctor --preflight' and resolve whatever it reports.",
            )
        if not self.backup_taken:
            raise SafetyError(
                "no verified backup has been taken in this session",
                remedy="Run 'boox backup' first. Writes are not permitted without one.",
            )

    def authorize(self, tier: Tier, target: str) -> None:
        """Check the token carries enough authority for this blast radius."""
        self.check_usable()
        if tier is Tier.CATASTROPHIC and not self.expert_unlocked:
            raise SafetyError(
                f"{target} is classified {tier.label} and the expert gate is not unlocked",
                remedy=(
                    "This partition is part of the boot chain or the radio. Getting it "
                    "wrong may need an EDL cable or test points to recover. If you really "
                    "mean it, use the dedicated command and pass --i-understand."
                ),
            )
        if tier is not Tier.SAFE and not self.golden_firmware_available:
            warn(
                f"{target} is {tier.label} and no golden firmware is available as a "
                "second restore source; only the device backup stands behind this write."
            )


class DeviceSession:
    """A connected device, plus the rules for touching it."""

    def __init__(
        self,
        backend: EdlBackend,
        workdir: Path,
        journal: Journal,
        *,
        dry_run: bool = False,
        profile_id: str = "unknown",
    ) -> None:
        self.backend = backend
        self.workdir = Path(workdir)
        self.workdir.mkdir(parents=True, exist_ok=True)
        self.journal = journal
        self.dry_run = dry_run
        self.profile_id = profile_id
        self._identity: DeviceIdentity | None = None
        self._table: PartitionTable | None = None

    # ---- discovery ------------------------------------------------------------

    @property
    def identity(self) -> DeviceIdentity:
        if self._identity is None:
            self._identity = self.backend.identify()
        return self._identity

    @property
    def table(self) -> PartitionTable:
        if self._table is None:
            self._table = self.backend.partition_table()
        return self._table

    def require_same_device(self, expected: DeviceIdentity) -> None:
        problems = mismatch(expected, self.identity)
        if problems:
            raise SafetyError(
                "this is not the device the backup came from:\n  "
                + "\n  ".join(problems),
                remedy="Connect the original tablet, or take a fresh backup of this one.",
            )

    # ---- reads ----------------------------------------------------------------

    def read(self, partition: str, dest: Path | None = None) -> Path:
        dest = dest or (self.workdir / f"{partition}.img")
        self.backend.read_partition(partition, dest)
        return dest

    def read_twice(self, partition: str) -> tuple[Path, str]:
        """Read a partition twice and require the results to agree.

        A cable or hub that corrupts transfers will usually produce two
        different reads. Finding that out while reading is free; finding it out
        while writing is not.
        """
        first = self.read(partition, self.workdir / f"{partition}.img")
        second = self.read(partition, self.workdir / f"{partition}.verify.img")
        a, b = sha256_file(first), sha256_file(second)
        second.unlink(missing_ok=True)
        if a != b:
            raise SafetyError(
                f"two consecutive reads of {partition} disagree ({short(a)} vs {short(b)})",
                remedy=(
                    "The USB link is not reliable. Change cable or port, avoid hubs, "
                    "and do not write anything until two reads match."
                ),
            )
        return first, a

    # ---- writes ---------------------------------------------------------------

    def write(
        self,
        partition: str,
        source: Path,
        *,
        token: WriteToken,
        report: Report,
        backup: Path | None,
        tier_overrides: dict[str, str] | None = None,
    ) -> None:
        """Write ``source`` to ``partition``, or refuse and explain why."""
        source = Path(source)
        tier = classify(partition, tier_overrides)
        token.authorize(tier, partition)

        if not report.ok:
            report.raise_if_failed()
        if report.target != partition:
            raise SafetyError(
                f"verification report is for {report.target!r} but the write targets "
                f"{partition!r}",
                remedy="This is a bug in the calling code; refusing to write.",
            )
        if backup is None or not Path(backup).is_file():
            raise SafetyError(
                f"no backup of {partition} is on hand",
                remedy="Every write must have something to roll back to. Run 'boox backup'.",
            )

        digest = sha256_file(source)
        entry = self.journal.begin(
            "write",
            partition,
            source=str(source),
            source_sha256=digest,
            backup=str(backup),
            tier=tier.label,
            profile=self.profile_id,
            dry_run=self.dry_run,
        )

        if self.dry_run:
            info(f"dry run: would write {source.name} ({short(digest)}) to {partition}")
            self.journal.done(entry, dry_run=True)
            return

        step(f"writing {source.name} -> {partition} [{tier.label}]")
        try:
            self.backend.write_partition(partition, source)
        except Exception as exc:
            self.journal.failed(entry, f"write failed: {exc}")
            raise

        # Read back. This is not optional: a write that reported success but
        # landed wrong is the failure mode that turns into a brick on reboot.
        try:
            readback = self.read(partition, self.workdir / f"{partition}.readback.img")
            actual = sha256_file(readback)
        except Exception as exc:
            self.journal.failed(entry, f"read-back failed: {exc}")
            raise SafetyError(
                f"{partition} was written but could not be read back: {exc}",
                remedy=(
                    "Do NOT reboot the device. Re-run this command; if the read still "
                    "fails, run 'boox rescue' while the device is still in EDL."
                ),
            ) from exc

        if not _matches(readback, source):
            warn(f"{partition}: read-back does not match what we sent. Rolling back.")
            self._rollback(partition, Path(backup), entry, actual, digest)
            raise SafetyError(
                f"{partition}: read-back mismatch (wrote {short(digest)}, "
                f"device holds {short(actual)}) -- the backup has been restored",
                remedy="The partition is back to its previous contents. Do not reboot yet.",
            )

        readback.unlink(missing_ok=True)
        self.journal.done(entry, readback_sha256=actual)
        ok(f"{partition} written and verified ({short(digest)})")

    def _rollback(
        self, partition: str, backup: Path, entry: str, actual: str, intended: str
    ) -> None:
        try:
            self.backend.write_partition(partition, backup)
            restored = self.read(partition, self.workdir / f"{partition}.rollback.img")
            if _matches(restored, backup):
                self.journal.rolled_back(
                    entry, readback_sha256=actual, intended_sha256=intended, restored=str(backup)
                )
                ok(f"{partition} restored from backup")
                restored.unlink(missing_ok=True)
                return
            self.journal.failed(
                entry, "rollback wrote but did not verify", restored=str(backup)
            )
        except Exception as exc:  # pragma: no cover - depends on hardware failure
            self.journal.failed(entry, f"rollback failed: {exc}", restored=str(backup))
        raise SafetyError(
            f"{partition} is in an unknown state and the rollback did not verify",
            remedy=(
                f"Do NOT reboot. Keep the device in EDL and run:\n"
                f"    boox rescue --partition {partition} --from {backup}"
            ),
        )

    def erase(self, partition: str, *, token: WriteToken, backup: Path | None,
              tier_overrides: dict[str, str] | None = None) -> None:
        tier = classify(partition, tier_overrides)
        token.authorize(tier, partition)
        if backup is None or not Path(backup).is_file():
            raise SafetyError(f"refusing to erase {partition} without a backup on hand")
        entry = self.journal.begin(
            "erase", partition, backup=str(backup), tier=tier.label, dry_run=self.dry_run
        )
        if self.dry_run:
            info(f"dry run: would erase {partition}")
            self.journal.done(entry, dry_run=True)
            return
        try:
            self.backend.erase_partition(partition)
        except Exception as exc:
            self.journal.failed(entry, f"erase failed: {exc}")
            raise
        self.journal.done(entry)
        ok(f"{partition} erased")

    def reset(self) -> None:
        if self.dry_run:
            info("dry run: would reboot the device out of EDL")
            return
        self.backend.reset()


def _matches(candidate: Path, source: Path) -> bool:
    """Compare a read-back against what we sent, ignoring trailing zero padding.

    A partition read returns the whole partition, so it is legitimately longer
    than the image we wrote; everything past the image must be zero.
    """
    written = source.read_bytes()
    got = candidate.read_bytes()
    if len(got) < len(written):
        return False
    if got[: len(written)] != written:
        return False
    return not got[len(written):].strip(b"\x00")
