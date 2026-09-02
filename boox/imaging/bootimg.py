"""Android boot image parsing (header versions 0-4) and vendor_boot.

We parse these ourselves rather than shelling out to ``magiskboot`` because the
single most important safety check in this tool -- proving a candidate image
carries the *same kernel* as the image it claims to be derived from -- only
needs the kernel section, and the kernel is stored uncompressed in the boot
image.  Doing it in-process means the check cannot be skipped just because an
external binary is missing.

Reference: AOSP ``system/tools/mkbootimg/include/bootimg/bootimg.h``.
"""

from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass, field

from boox.errors import ImageError

BOOT_MAGIC = b"ANDROID!"
VENDOR_BOOT_MAGIC = b"VNDRBOOT"
VBMETA_MAGIC = b"AVB0"
AVB_FOOTER_MAGIC = b"AVBf"
ELF_MAGIC = b"\x7fELF"
SPARSE_MAGIC = b"\x3a\xff\x26\xed"

# A page size outside this range means we mis-parsed something.
MIN_PAGE_SIZE = 2048
MAX_PAGE_SIZE = 1 << 20
MAX_HEADER_VERSION = 4


def _align(value: int, page_size: int) -> int:
    """Round ``value`` up to a whole number of pages."""
    if page_size <= 0:
        raise ImageError(f"invalid page size {page_size}")
    return ((value + page_size - 1) // page_size) * page_size


@dataclass(frozen=True)
class Section:
    """A byte range inside an image."""

    name: str
    offset: int
    size: int

    @property
    def end(self) -> int:
        return self.offset + self.size


@dataclass
class BootImage:
    """A parsed boot / init_boot / recovery / vendor_boot image."""

    kind: str  # "boot" or "vendor_boot"
    header_version: int
    page_size: int
    os_version_raw: int
    cmdline: str
    sections: dict[str, Section] = field(default_factory=dict)
    _data: bytes = b""

    def section_bytes(self, name: str) -> bytes:
        sec = self.sections.get(name)
        if sec is None or sec.size == 0:
            return b""
        return self._data[sec.offset : sec.end]

    @property
    def kernel(self) -> bytes:
        return self.section_bytes("kernel")

    @property
    def ramdisk(self) -> bytes:
        # vendor_boot names its ramdisk differently; normalise for callers.
        if "ramdisk" in self.sections:
            return self.section_bytes("ramdisk")
        return self.section_bytes("vendor_ramdisk")

    def kernel_sha256(self) -> str:
        return hashlib.sha256(self.kernel).hexdigest()

    def ramdisk_sha256(self) -> str:
        return hashlib.sha256(self.ramdisk).hexdigest()

    @property
    def os_version(self) -> str:
        """Decode the packed os_version/patch_level field into 'A.B.C / YYYY-MM'."""
        raw = self.os_version_raw
        if raw == 0:
            return "unknown"
        version = raw >> 11
        patch = raw & 0x7FF
        a, b, c = (version >> 14) & 0x7F, (version >> 7) & 0x7F, version & 0x7F
        year, month = ((patch >> 4) & 0x7F) + 2000, patch & 0xF
        return f"{a}.{b}.{c} / {year:04d}-{month:02d}"

    @property
    def payload_end(self) -> int:
        """Offset just past the last real section; everything after is padding."""
        return max((s.end for s in self.sections.values()), default=self.page_size)

    def describe(self) -> str:
        parts = [f"{self.kind} v{self.header_version}", f"page={self.page_size}"]
        for name in ("kernel", "ramdisk", "vendor_ramdisk", "second", "dtb", "recovery_dtbo"):
            sec = self.sections.get(name)
            if sec and sec.size:
                parts.append(f"{name}={sec.size}")
        return ", ".join(parts)


def detect_kind(data: bytes) -> str:
    """Classify a blob by magic. Returns a coarse type name, never raises."""
    if len(data) < 8:
        return "empty" if not data.strip(b"\x00") else "unknown"
    if data.startswith(BOOT_MAGIC):
        return "boot"
    if data.startswith(VENDOR_BOOT_MAGIC):
        return "vendor_boot"
    if data.startswith(VBMETA_MAGIC):
        return "vbmeta"
    if data.startswith(ELF_MAGIC):
        return "elf"
    if data.startswith(SPARSE_MAGIC):
        return "sparse"
    if not data.strip(b"\x00"):
        return "empty"
    return "unknown"


def _check_span(data: bytes, name: str, offset: int, size: int) -> Section:
    if size < 0:
        raise ImageError(f"{name} has negative size ({size})")
    if offset < 0:
        raise ImageError(f"{name} has negative offset ({offset})")
    if offset + size > len(data):
        raise ImageError(
            f"{name} runs past the end of the image "
            f"(needs {offset + size} bytes, image is {len(data)})",
            remedy="The image is truncated or is not the format its header claims.",
        )
    return Section(name, offset, size)


def _parse_boot_v0_v2(data: bytes) -> BootImage:
    if len(data) < 1648:
        raise ImageError(f"boot image too small for a v0-v2 header ({len(data)} bytes)")
    (
        kernel_size,
        _kernel_addr,
        ramdisk_size,
        _ramdisk_addr,
        second_size,
        _second_addr,
        _tags_addr,
        page_size,
        header_version,
        os_version,
    ) = struct.unpack_from("<10I", data, 8)

    if page_size < MIN_PAGE_SIZE or page_size > MAX_PAGE_SIZE or page_size & (page_size - 1):
        raise ImageError(
            f"implausible page size {page_size}",
            remedy="This does not look like a real Android boot image.",
        )
    if header_version > 2:
        raise ImageError(f"header version {header_version} parsed with the v0-v2 layout")

    cmdline = data[64:576].split(b"\x00", 1)[0].decode("utf-8", "replace")
    extra = data[608:1632].split(b"\x00", 1)[0].decode("utf-8", "replace")
    if extra:
        cmdline = f"{cmdline}{extra}"

    recovery_dtbo_size = dtb_size = 0
    if header_version >= 1:
        recovery_dtbo_size = struct.unpack_from("<I", data, 1632)[0]
    if header_version >= 2:
        dtb_size = struct.unpack_from("<I", data, 1648)[0]

    offset = _align(page_size, page_size)  # header occupies exactly one page
    sections: dict[str, Section] = {}
    for name, size in (
        ("kernel", kernel_size),
        ("ramdisk", ramdisk_size),
        ("second", second_size),
        ("recovery_dtbo", recovery_dtbo_size),
        ("dtb", dtb_size),
    ):
        if size:
            sections[name] = _check_span(data, name, offset, size)
        offset += _align(size, page_size)

    if kernel_size == 0:
        raise ImageError(
            "boot image declares a zero-length kernel",
            remedy="A boot partition with no kernel will not boot. Refusing to treat this as valid.",
        )

    return BootImage(
        kind="boot",
        header_version=header_version,
        page_size=page_size,
        os_version_raw=os_version,
        cmdline=cmdline,
        sections=sections,
        _data=data,
    )


def _parse_boot_v3_v4(data: bytes) -> BootImage:
    if len(data) < 1584:
        raise ImageError(f"boot image too small for a v3/v4 header ({len(data)} bytes)")
    kernel_size, ramdisk_size, os_version, _header_size = struct.unpack_from("<4I", data, 8)
    header_version = struct.unpack_from("<I", data, 40)[0]
    if header_version not in (3, 4):
        raise ImageError(f"header version {header_version} parsed with the v3/v4 layout")
    cmdline = data[44:1580].split(b"\x00", 1)[0].decode("utf-8", "replace")

    page_size = 4096  # fixed by the v3+ spec
    signature_size = 0
    if header_version == 4:
        signature_size = struct.unpack_from("<I", data, 1580)[0]

    offset = page_size
    sections: dict[str, Section] = {}
    for name, size in (("kernel", kernel_size), ("ramdisk", ramdisk_size)):
        if size:
            sections[name] = _check_span(data, name, offset, size)
        offset += _align(size, page_size)
    if signature_size:
        # boot_signature is best-effort: some vendors leave the field set but
        # trim the partition, so a missing tail here is not fatal.
        if offset + signature_size <= len(data):
            sections["boot_signature"] = Section("boot_signature", offset, signature_size)

    if kernel_size == 0:
        raise ImageError(
            "boot image declares a zero-length kernel",
            remedy="A boot partition with no kernel will not boot. Refusing to treat this as valid.",
        )

    return BootImage(
        kind="boot",
        header_version=header_version,
        page_size=page_size,
        os_version_raw=os_version,
        cmdline=cmdline,
        sections=sections,
        _data=data,
    )


def _parse_vendor_boot(data: bytes) -> BootImage:
    if len(data) < 2112:
        raise ImageError(f"vendor_boot image too small ({len(data)} bytes)")
    header_version, page_size, _kernel_addr, _ramdisk_addr, vendor_ramdisk_size = struct.unpack_from(
        "<5I", data, 8
    )
    if header_version not in (3, 4):
        raise ImageError(f"unsupported vendor_boot header version {header_version}")
    if page_size < MIN_PAGE_SIZE or page_size > MAX_PAGE_SIZE or page_size & (page_size - 1):
        raise ImageError(f"implausible vendor_boot page size {page_size}")

    cmdline = data[28:2076].split(b"\x00", 1)[0].decode("utf-8", "replace")
    header_size = struct.unpack_from("<I", data, 2096)[0]
    dtb_size = struct.unpack_from("<I", data, 2100)[0]

    # The header is padded up to a page boundary; with a small page size it can
    # span more than one page, so align the real header size rather than
    # assuming a single page.
    if header_size < 2112 or header_size > MAX_PAGE_SIZE:
        header_size = 2112 if header_version == 3 else 2128
    offset = _align(header_size, page_size)
    sections: dict[str, Section] = {}
    for name, size in (("vendor_ramdisk", vendor_ramdisk_size), ("dtb", dtb_size)):
        if size:
            sections[name] = _check_span(data, name, offset, size)
        offset += _align(size, page_size)

    return BootImage(
        kind="vendor_boot",
        header_version=header_version,
        page_size=page_size,
        os_version_raw=0,
        cmdline=cmdline,
        sections=sections,
        _data=data,
    )


def parse(data: bytes) -> BootImage:
    """Parse a boot-family image. Raises ``ImageError`` if it is not one."""
    kind = detect_kind(data)
    if kind == "vendor_boot":
        return _parse_vendor_boot(data)
    if kind != "boot":
        raise ImageError(
            f"not an Android boot image (detected: {kind})",
            remedy="Expected the magic 'ANDROID!' at offset 0.",
        )
    # header_version lives at a different offset in v0-2 vs v3+, so read both
    # and let the value decide which layout applies.
    v012 = struct.unpack_from("<I", data, 40)[0] if len(data) >= 44 else 0
    if v012 in (3, 4):
        return _parse_boot_v3_v4(data)
    if v012 > MAX_HEADER_VERSION:
        raise ImageError(
            f"unsupported boot header version {v012}",
            remedy="This tool understands boot image versions 0 through 4.",
        )
    return _parse_boot_v0_v2(data)


def has_avb_footer(data: bytes) -> bool:
    """True if the image carries an AVB footer in its final 64 bytes."""
    return len(data) >= 64 and data[-64:-60] == AVB_FOOTER_MAGIC
