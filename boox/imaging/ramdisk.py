"""Ramdisk decompression and Magisk detection.

The verifier needs to answer one question about a candidate boot image: *has
this actually been patched by Magisk, or did the user hand us a stock image by
mistake?*  Answering it means getting inside the ramdisk.

Where the ramdisk uses a codec the standard library cannot open (lz4, zstd) we
say so explicitly rather than guessing.  ``UNKNOWN`` is a distinct answer from
``NOT_PATCHED`` and callers must treat it as such.
"""

from __future__ import annotations

import bz2
import gzip
import lzma
import struct
from dataclasses import dataclass
from enum import Enum

CPIO_NEWC_MAGIC = (b"070701", b"070702")

# Files Magisk adds to (or moves within) the ramdisk. Seeing any of these means
# the image has been patched.
MAGISK_MARKERS = (
    ".backup/.magisk",
    "overlay.d",
    "magisk",
    "magisk32",
    "magisk64",
    "magiskinit",
    "init.magisk.rc",
)

# APatch / KernelSU leave their own traces; worth recognising so we can give a
# precise message instead of "not Magisk".
OTHER_ROOT_MARKERS = ("kernelsu", "apatch", "ksud")


class PatchState(str, Enum):
    PATCHED = "patched"
    NOT_PATCHED = "not_patched"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class RamdiskInfo:
    compression: str
    state: PatchState
    evidence: str
    entries: tuple[str, ...] = ()

    @property
    def patched(self) -> bool:
        return self.state is PatchState.PATCHED


def detect_compression(data: bytes) -> str:
    if data.startswith(b"\x1f\x8b"):
        return "gzip"
    if data.startswith(b"\xfd7zXZ\x00"):
        return "xz"
    if data.startswith(b"\x5d\x00\x00"):
        return "lzma"
    if data.startswith(b"BZh"):
        return "bzip2"
    if data.startswith(b"\x04\x22\x4d\x18"):
        return "lz4"
    if data.startswith(b"\x02\x21\x4c\x18"):
        return "lz4_legacy"
    if data.startswith(b"\x28\xb5\x2f\xfd"):
        return "zstd"
    if data[:6] in CPIO_NEWC_MAGIC:
        return "none"
    if not data:
        return "empty"
    return "unknown"


def decompress(data: bytes) -> tuple[str, bytes | None]:
    """Return ``(codec, plain_bytes)``; ``plain_bytes`` is None if unsupported."""
    codec = detect_compression(data)
    try:
        if codec == "none":
            return codec, data
        if codec == "gzip":
            return codec, gzip.decompress(data)
        if codec in ("xz", "lzma"):
            return codec, lzma.decompress(data)
        if codec == "bzip2":
            return codec, bz2.decompress(data)
        if codec in ("lz4", "lz4_legacy"):
            return codec, _try_lz4(data, legacy=codec == "lz4_legacy")
        if codec == "zstd":
            return codec, _try_zstd(data)
    except Exception:
        # A corrupt or truncated ramdisk is itself a finding; report it as
        # undecodable rather than crashing the verifier.
        return codec, None
    return codec, None


def _try_lz4(data: bytes, *, legacy: bool) -> bytes | None:
    try:
        import lz4.frame  # type: ignore[import-not-found]
    except ImportError:
        return None
    if not legacy:
        return lz4.frame.decompress(data)
    # Legacy lz4 is a sequence of 4-byte-length-prefixed blocks after the magic.
    try:
        import lz4.block  # type: ignore[import-not-found]
    except ImportError:
        return None
    out = bytearray()
    pos = 4
    while pos + 4 <= len(data):
        (block_len,) = struct.unpack_from("<I", data, pos)
        pos += 4
        if block_len == 0 or pos + block_len > len(data):
            break
        out += lz4.block.decompress(
            data[pos : pos + block_len], uncompressed_size=8 * 1024 * 1024
        )
        pos += block_len
    return bytes(out) or None


def _try_zstd(data: bytes) -> bytes | None:
    try:
        from compression import zstd  # type: ignore[import-not-found]  # Python 3.14+

        return zstd.decompress(data)
    except ImportError:
        pass
    try:
        import zstandard  # type: ignore[import-not-found]

        return zstandard.ZstdDecompressor().decompress(data, max_output_size=256 * 1024 * 1024)
    except ImportError:
        return None


def list_cpio_entries(data: bytes, limit: int = 20000) -> list[str]:
    """List file names in a newc-format cpio archive.

    Tolerant by design: a malformed entry stops the walk and we return what we
    have, because a partial listing is still useful evidence.
    """
    names: list[str] = []
    pos = 0
    while pos + 110 <= len(data) and len(names) < limit:
        if data[pos : pos + 6] not in CPIO_NEWC_MAGIC:
            break
        try:
            filesize = int(data[pos + 54 : pos + 62], 16)
            namesize = int(data[pos + 94 : pos + 102], 16)
        except ValueError:
            break
        if namesize <= 0 or namesize > 4096:
            break
        name_start = pos + 110
        name = data[name_start : name_start + namesize - 1].decode("utf-8", "replace")
        if name == "TRAILER!!!":
            break
        names.append(name)
        pos = name_start + namesize
        pos += (-pos) % 4
        pos += filesize
        pos += (-pos) % 4
    return names


def inspect(ramdisk: bytes) -> RamdiskInfo:
    """Classify a ramdisk as Magisk-patched, stock, or undeterminable."""
    if not ramdisk:
        return RamdiskInfo("empty", PatchState.UNKNOWN, "image has no ramdisk section")

    codec, plain = decompress(ramdisk)
    if plain is None:
        return RamdiskInfo(
            codec,
            PatchState.UNKNOWN,
            f"ramdisk is {codec}-compressed and this Python cannot decompress it",
        )

    entries = list_cpio_entries(plain)
    lowered = [e.lower() for e in entries]

    hits = [m for m in MAGISK_MARKERS if any(e == m or e.endswith("/" + m) for e in lowered)]
    if hits:
        return RamdiskInfo(
            codec, PatchState.PATCHED, f"ramdisk contains {', '.join(hits)}", tuple(entries)
        )

    others = [m for m in OTHER_ROOT_MARKERS if any(m in e for e in lowered)]
    if others:
        return RamdiskInfo(
            codec,
            PatchState.PATCHED,
            f"ramdisk carries a non-Magisk root solution ({', '.join(others)})",
            tuple(entries),
        )

    if not entries:
        # Decompressed, but not a cpio we understand. Fall back to a raw scan so
        # we do not claim "stock" about something we did not really read.
        if b"magisk" in plain.lower():
            return RamdiskInfo(
                codec, PatchState.PATCHED, "'magisk' found in ramdisk bytes", ()
            )
        return RamdiskInfo(
            codec, PatchState.UNKNOWN, "ramdisk decompressed but is not a newc cpio archive"
        )

    return RamdiskInfo(
        codec,
        PatchState.NOT_PATCHED,
        f"{len(entries)} cpio entries, no root-solution markers",
        tuple(entries),
    )
