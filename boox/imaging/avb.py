"""Android Verified Boot (AVB) structures.

We do not verify signatures -- we cannot, without the OEM public key -- but we
do need to read two things:

* whether the device's ``vbmeta`` has verification disabled (which is what makes
  a Magisk-patched boot image bootable on a locked bootloader), and
* whether an image carries an AVB footer, so the verifier can tell a bare boot
  image apart from one with AVB metadata appended.

All AVB integers are big-endian.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass

from boox.errors import ImageError

VBMETA_MAGIC = b"AVB0"
FOOTER_MAGIC = b"AVBf"
VBMETA_HEADER_SIZE = 256
FOOTER_SIZE = 64

FLAG_HASHTREE_DISABLED = 1 << 0
FLAG_VERIFICATION_DISABLED = 1 << 1


@dataclass(frozen=True)
class VBMetaHeader:
    version_major: int
    version_minor: int
    algorithm_type: int
    rollback_index: int
    flags: int
    release_string: str

    @property
    def verification_disabled(self) -> bool:
        return bool(self.flags & FLAG_VERIFICATION_DISABLED)

    @property
    def hashtree_disabled(self) -> bool:
        return bool(self.flags & FLAG_HASHTREE_DISABLED)

    @property
    def signed(self) -> bool:
        return self.algorithm_type != 0

    def describe(self) -> str:
        bits = []
        if self.verification_disabled:
            bits.append("verification DISABLED")
        if self.hashtree_disabled:
            bits.append("hashtree disabled")
        if not bits:
            bits.append("verification enforced")
        signing = "signed" if self.signed else "unsigned"
        return (
            f"vbmeta {self.version_major}.{self.version_minor} ({signing}, "
            f"algo={self.algorithm_type}, rollback={self.rollback_index}): " + ", ".join(bits)
        )


@dataclass(frozen=True)
class AvbFooter:
    original_image_size: int
    vbmeta_offset: int
    vbmeta_size: int


def parse_vbmeta(data: bytes) -> VBMetaHeader:
    """Parse a vbmeta partition image."""
    if len(data) < VBMETA_HEADER_SIZE:
        raise ImageError(f"vbmeta image too small ({len(data)} bytes)")
    if not data.startswith(VBMETA_MAGIC):
        raise ImageError(
            "not a vbmeta image (missing 'AVB0' magic)",
            remedy="Check that you are pointing at the vbmeta partition and not something else.",
        )
    version_major, version_minor = struct.unpack_from(">2I", data, 4)
    algorithm_type = struct.unpack_from(">I", data, 28)[0]
    rollback_index = struct.unpack_from(">Q", data, 112)[0]
    flags = struct.unpack_from(">I", data, 120)[0]
    release_string = data[128:176].split(b"\x00", 1)[0].decode("utf-8", "replace")
    return VBMetaHeader(
        version_major=version_major,
        version_minor=version_minor,
        algorithm_type=algorithm_type,
        rollback_index=rollback_index,
        flags=flags,
        release_string=release_string,
    )


def read_footer(data: bytes) -> AvbFooter | None:
    """Return the AVB footer from the last 64 bytes, or None if absent."""
    if len(data) < FOOTER_SIZE:
        return None
    tail = data[-FOOTER_SIZE:]
    if not tail.startswith(FOOTER_MAGIC):
        return None
    original_image_size, vbmeta_offset, vbmeta_size = struct.unpack_from(">3Q", tail, 12)
    return AvbFooter(original_image_size, vbmeta_offset, vbmeta_size)


def find_footer_in_partition(data: bytes, block_size: int = 4096) -> AvbFooter | None:
    """Locate an AVB footer in a full partition dump.

    A partition read gives us the whole partition, and the footer sits in the
    last block of the *image*, not of the partition, so it is usually followed
    by zero padding.  Scan backwards a bounded number of blocks rather than only
    looking at the very end.
    """
    footer = read_footer(data)
    if footer is not None:
        return footer
    # Walk back over trailing zero padding to the last non-zero block.
    end = len(data)
    while end > 0 and not data[max(0, end - block_size) : end].strip(b"\x00"):
        end -= block_size
    if end <= 0 or end > len(data):
        return None
    return read_footer(data[:end])
