"""The image verifier.

Nothing in this tool writes bytes to a partition unless they have been through
here first.  The checks exist because of two specific, documented ways people
have bricked these tablets:

* writing an image taken from a *different device model* to ``boot_a``, and
* writing to the slot the device is not currently booting from, then "fixing"
  it by writing the other slot as well.

So the two load-bearing checks are **provenance** (this image demonstrably came
from an image we trust for this device) and **explicit slot resolution** (we
never infer a slot).  The rest catch more ordinary mistakes: wrong file, wrong
partition, truncated download, forgot to actually patch it.

A check marked ``fatal`` blocks the write. A non-fatal check that fails is a
warning the operator must read but may proceed past.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from boox.errors import ImageError, VerificationError
from boox.imaging import avb, bootimg, ramdisk as ramdisk_mod
from boox.imaging.gpt import PartitionTable
from boox.safety.tiers import base_name
from boox.transport.sahara import DeviceIdentity, mismatch
from boox.util import sha256_bytes, short

# What magic each partition class must start with. Anything not listed here has
# no format we can check, which is itself reported.
EXPECTED_KIND = {
    "boot": "boot",
    "init_boot": "boot",
    "recovery": "boot",
    "vendor_boot": "vendor_boot",
    "vbmeta": "vbmeta",
    "vbmeta_system": "vbmeta",
    "vbmeta_vendor": "vbmeta",
    "abl": "elf",
    "xbl": "elf",
    "xbl_config": "elf",
    "tz": "elf",
    "hyp": "elf",
    "devcfg": "elf",
}

# Partitions that legitimately contain a boot image with no kernel.
KERNEL_LESS = {"init_boot"}

# Fraction of the reference ramdisk's entries that must still be present in a
# candidate for a kernel-less image to count as derived from it.
RAMDISK_OVERLAP_THRESHOLD = 0.6


@dataclass(frozen=True)
class Check:
    name: str
    passed: bool
    detail: str
    fatal: bool = True

    @property
    def symbol(self) -> str:
        if self.passed:
            return "ok"
        return "FAIL" if self.fatal else "warn"


@dataclass(frozen=True)
class Reference:
    """A known-good image the candidate may legitimately be derived from."""

    label: str      # e.g. "device backup boot_a" or "stock firmware boot.img"
    data: bytes


@dataclass
class Report:
    target: str
    checks: list[Check] = field(default_factory=list)

    def add(self, name: str, passed: bool, detail: str, *, fatal: bool = True) -> None:
        self.checks.append(Check(name, passed, detail, fatal))

    overrides: dict[str, str] = field(default_factory=dict)

    def override(self, name: str, reason: str) -> None:
        """Acknowledge one failing check by name, recording why.

        This exists for exactly one situation: deliberately writing a
        bootloader that by definition cannot match any reference for this
        device. It is narrow on purpose -- it takes a single check name, and
        the reason is written into the journal alongside the write.
        """
        if not any(c.name == name for c in self.checks):
            raise VerificationError(f"cannot override {name!r}: no such check in this report")
        self.overrides[name] = reason

    @property
    def failures(self) -> list[Check]:
        return [
            c for c in self.checks
            if not c.passed and c.fatal and c.name not in self.overrides
        ]

    @property
    def warnings(self) -> list[Check]:
        return [c for c in self.checks if not c.passed and not c.fatal]

    @property
    def ok(self) -> bool:
        return not self.failures

    def raise_if_failed(self) -> None:
        if self.ok:
            return
        lines = [f"  - {c.name}: {c.detail}" for c in self.failures]
        raise VerificationError(
            f"{self.target}: image verification failed, nothing was written\n"
            + "\n".join(lines),
            remedy="Fix the image or pick the right file. The device is untouched.",
        )

    def render(self) -> str:
        lines = []
        for c in self.checks:
            symbol = "ackd" if (not c.passed and c.name in self.overrides) else c.symbol
            lines.append(f"  [{symbol:>4}] {c.name}: {c.detail}")
            if c.name in self.overrides:
                lines.append(f"         acknowledged: {self.overrides[c.name]}")
        return "\n".join(lines)


def _parse_boot(data: bytes, allow_empty_kernel: bool) -> bootimg.BootImage | None:
    try:
        return bootimg.parse(data, allow_empty_kernel=allow_empty_kernel)
    except ImageError:
        return None


def _provenance(
    candidate: bootimg.BootImage,
    references: list[Reference],
    allow_empty_kernel: bool,
) -> tuple[bool, str]:
    """Decide whether ``candidate`` was derived from one of ``references``.

    For an image with a kernel this is exact: Magisk rewrites the ramdisk and
    leaves the kernel alone, so a byte-identical kernel is strong evidence, and
    a different kernel means the image is from another build or another device.

    ``init_boot`` has no kernel to compare, so we fall back to matching the
    header fingerprint (which encodes the Android version and security patch
    level of the build) and requiring most of the reference ramdisk's files to
    still be present.
    """
    if not references:
        return False, "no trusted reference image was available to compare against"

    candidate_kernel = candidate.kernel
    tried: list[str] = []

    for ref in references:
        parsed = _parse_boot(ref.data, allow_empty_kernel)
        if parsed is None:
            tried.append(f"{ref.label} (unparseable)")
            continue

        if candidate_kernel and parsed.kernel:
            if candidate.kernel_sha256() == parsed.kernel_sha256():
                return True, (
                    f"kernel is byte-identical to {ref.label} "
                    f"(sha256 {short(candidate.kernel_sha256())})"
                )
            tried.append(
                f"{ref.label} kernel {short(parsed.kernel_sha256())} "
                f"!= candidate {short(candidate.kernel_sha256())}"
            )
            continue

        if candidate_kernel or parsed.kernel:
            tried.append(f"{ref.label} (one image has a kernel and the other does not)")
            continue

        # Kernel-less: match on header fingerprint plus ramdisk file overlap.
        same_header = (
            candidate.header_version == parsed.header_version
            and candidate.page_size == parsed.page_size
            and candidate.os_version_raw == parsed.os_version_raw
        )
        if not same_header:
            tried.append(f"{ref.label} (header fingerprint differs)")
            continue

        ref_info = ramdisk_mod.inspect(parsed.ramdisk)
        ref_entries = set(ref_info.entries)
        cand_entries = set(ramdisk_mod.inspect(candidate.ramdisk).entries)
        if not ref_entries:
            # Say *why* we could not read it. Without the codec name and the
            # install command this failure is undiagnosable, and it blocks the
            # main rooting path on any device whose init_boot uses lz4.
            tried.append(f"{ref.label}: {ref_info.evidence}")
            continue
        overlap = len(ref_entries & cand_entries) / len(ref_entries)
        if overlap >= RAMDISK_OVERLAP_THRESHOLD:
            return True, (
                f"header matches {ref.label} and {overlap:.0%} of its ramdisk "
                "entries are still present"
            )
        tried.append(f"{ref.label} (only {overlap:.0%} ramdisk overlap)")

    return False, "does not match any trusted reference: " + "; ".join(tried)


def verify_candidate(
    data: bytes,
    *,
    target: str,
    table: PartitionTable | None = None,
    references: list[Reference] | None = None,
    require_root_patch: bool = False,
    expect_identity: DeviceIdentity | None = None,
    actual_identity: DeviceIdentity | None = None,
) -> Report:
    """Run every applicable check against a candidate image.

    ``target`` is the concrete partition name, slot suffix included.
    """
    report = Report(target=target)
    references = references or []
    base = base_name(target)
    expected_kind = EXPECTED_KIND.get(base)
    allow_empty_kernel = base in KERNEL_LESS

    # --- the image is actually something -------------------------------------
    report.add("non_empty", bool(data), f"{len(data)} bytes")
    if not data:
        return report
    report.add(
        "not_blank",
        bool(data.strip(b"\x00")),
        "image is not entirely zeroes" if data.strip(b"\x00") else "image is all zero bytes",
    )

    # --- it fits ---------------------------------------------------------------
    if table is not None:
        part = table.get(target)
        if part is None:
            report.add("partition_exists", False, f"{target} is not in the device's GPT")
            return report
        report.add("partition_exists", True, f"{target} is {part.size_bytes} bytes")
        report.add(
            "fits_partition",
            len(data) <= part.size_bytes,
            f"image {len(data)} bytes vs partition {part.size_bytes} bytes",
        )
        # A slotted base name must have been resolved to a concrete slot.
        if table.is_ab():
            slotted_bases = {p.base_name for p in table if p.slot}
            report.add(
                "slot_explicit",
                not (base in slotted_bases and part.slot is None),
                f"target resolves to {target}"
                if part.slot or base not in slotted_bases
                else f"{base} is slotted but {target} carries no slot suffix",
            )
    else:
        report.add(
            "partition_exists", True, "no partition table supplied; size not checked", fatal=False
        )

    # --- it is the right kind of thing ----------------------------------------
    detected = bootimg.detect_kind(data)
    if expected_kind:
        report.add(
            "magic_matches_target",
            detected == expected_kind,
            f"{target} expects a {expected_kind} image; this looks like {detected}",
        )
    else:
        report.add(
            "magic_matches_target",
            True,
            f"no known format for {base!r}; detected {detected} (not checked)",
            fatal=False,
        )

    # --- format-specific structure --------------------------------------------
    parsed: bootimg.BootImage | None = None
    if expected_kind in ("boot", "vendor_boot"):
        try:
            parsed = bootimg.parse(data, allow_empty_kernel=allow_empty_kernel)
            report.add("header_parses", True, parsed.describe())
        except ImageError as exc:
            report.add("header_parses", False, str(exc.message))
    elif expected_kind == "vbmeta":
        try:
            header = avb.parse_vbmeta(data)
            report.add("header_parses", True, header.describe())
        except ImageError as exc:
            report.add("header_parses", False, str(exc.message))

    # --- provenance: the check that matters most -------------------------------
    if parsed is not None:
        passed, detail = _provenance(parsed, references, allow_empty_kernel)
        report.add("provenance", passed, detail)
    elif expected_kind in ("boot", "vendor_boot"):
        report.add("provenance", False, "image did not parse, so provenance cannot be established")
    else:
        digest = sha256_bytes(data)
        match = next((r.label for r in references if sha256_bytes(r.data) == digest), None)
        report.add(
            "provenance",
            match is not None,
            f"byte-identical to {match}" if match else
            f"sha256 {short(digest)} matches no trusted reference for {base}",
            fatal=bool(references),
        )

    # --- did the user actually patch it? ---------------------------------------
    if require_root_patch:
        if parsed is None:
            report.add("root_patch_present", False, "cannot inspect a ramdisk we could not parse")
        else:
            info = ramdisk_mod.inspect(parsed.ramdisk)
            if info.state is ramdisk_mod.PatchState.PATCHED:
                report.add("root_patch_present", True, info.evidence)
            elif info.state is ramdisk_mod.PatchState.NOT_PATCHED:
                report.add(
                    "root_patch_present",
                    False,
                    "this is a stock ramdisk -- it was never patched. "
                    "Writing it would not grant root.",
                )
            else:
                report.add(
                    "root_patch_present",
                    False,
                    f"could not confirm a root patch ({info.evidence})",
                    fatal=False,
                )

            changed = any(
                (p := _parse_boot(ref.data, allow_empty_kernel)) is not None
                and p.ramdisk_sha256() != parsed.ramdisk_sha256()
                for ref in references
            ) if references else True
            report.add(
                "ramdisk_differs_from_stock",
                changed,
                "ramdisk differs from the reference"
                if changed
                else "ramdisk is byte-identical to stock, so nothing was patched",
            )

    # --- is this even the same tablet? ----------------------------------------
    if expect_identity is not None and actual_identity is not None:
        problems = mismatch(expect_identity, actual_identity)
        report.add(
            "device_binding",
            not problems,
            "; ".join(problems) if problems else
            f"device matches the backup ({actual_identity.fingerprint()})",
        )

    return report


def verify_file(path: Path, **kwargs) -> Report:
    return verify_candidate(Path(path).read_bytes(), **kwargs)
