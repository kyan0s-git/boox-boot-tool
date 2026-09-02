"""Builders for synthetic images, so the whole test suite runs without hardware."""

from __future__ import annotations

import gzip
import struct

CPIO_TRAILER = "TRAILER!!!"


def _cpio_entry(name: str, data: bytes = b"", mode: int = 0o100644) -> bytes:
    fields = [
        0,          # ino
        mode,       # mode
        0, 0, 1, 0, # uid, gid, nlink, mtime
        len(data),  # filesize
        0, 0, 0, 0, # dev/rdev
        len(name) + 1,
        0,          # check
    ]
    header = b"070701" + b"".join(b"%08X" % f for f in fields)
    out = bytearray(header + name.encode() + b"\x00")
    out += b"\x00" * ((-len(out)) % 4)
    out += data
    out += b"\x00" * ((-len(out)) % 4)
    return bytes(out)


def make_cpio(names: list[str]) -> bytes:
    out = bytearray()
    for name in names:
        out += _cpio_entry(name, b"x" * 16)
    out += _cpio_entry(CPIO_TRAILER)
    return bytes(out)


def make_ramdisk(names: list[str], codec: str = "gzip") -> bytes:
    raw = make_cpio(names)
    if codec == "gzip":
        return gzip.compress(raw)
    if codec == "none":
        return raw
    raise ValueError(f"unsupported test codec {codec}")


STOCK_RAMDISK_ENTRIES = [".", "init", "init.rc", "system", "system/bin", "fstab.qcom"]
MAGISK_RAMDISK_ENTRIES = STOCK_RAMDISK_ENTRIES + [
    "overlay.d",
    ".backup",
    ".backup/.magisk",
    "magiskinit",
]


def _pad(data: bytes, page_size: int) -> bytes:
    return data + b"\x00" * ((-len(data)) % page_size)


def build_boot_image(
    kernel: bytes,
    ramdisk: bytes,
    *,
    header_version: int = 2,
    page_size: int = 4096,
    os_version_raw: int = 0,
    cmdline: str = "console=ttyMSM0",
    pad_to: int | None = None,
) -> bytes:
    """Build a boot image with the given header version (0-4)."""
    if header_version >= 3:
        page_size = 4096
        header = bytearray(b"ANDROID!")
        header += struct.pack("<4I", len(kernel), len(ramdisk), os_version_raw,
                              1580 if header_version == 3 else 1584)
        header += b"\x00" * 16  # reserved
        header += struct.pack("<I", header_version)
        cmd = cmdline.encode()[:1535]
        header += cmd + b"\x00" * (1536 - len(cmd))
        if header_version == 4:
            header += struct.pack("<I", 0)  # signature_size
    else:
        header = bytearray(b"ANDROID!")
        header += struct.pack(
            "<10I",
            len(kernel), 0x8000, len(ramdisk), 0x1000000, 0, 0, 0x100,
            page_size, header_version, os_version_raw,
        )
        header += b"\x00" * 16                       # name
        cmd = cmdline.encode()[:511]
        header += cmd + b"\x00" * (512 - len(cmd))   # cmdline
        header += b"\x00" * 32                       # id
        header += b"\x00" * 1024                     # extra_cmdline
        header += struct.pack("<I", 0)               # recovery_dtbo_size (v1)
        header += struct.pack("<Q", 0)               # recovery_dtbo_offset
        header += struct.pack("<I", 1648)            # header_size
        header += struct.pack("<I", 0)               # dtb_size (v2)
        header += struct.pack("<Q", 0)               # dtb_addr

    out = _pad(bytes(header), page_size) + _pad(kernel, page_size) + _pad(ramdisk, page_size)
    if pad_to and len(out) < pad_to:
        out += b"\x00" * (pad_to - len(out))
    return out


def build_vbmeta(*, flags: int = 0, algorithm_type: int = 1, size: int = 8192) -> bytes:
    header = bytearray(b"\x00" * 256)
    header[0:4] = b"AVB0"
    struct.pack_into(">2I", header, 4, 1, 2)
    struct.pack_into(">I", header, 28, algorithm_type)
    struct.pack_into(">Q", header, 112, 0)
    struct.pack_into(">I", header, 120, flags)
    header[128:128 + 8] = b"avbtool\x00"
    return bytes(header) + b"\x00" * (size - 256)


def build_gpt(entries: list[tuple[str, int, int]], sector_size: int = 512) -> bytes:
    """Build a minimal but real GPT. ``entries`` is (name, start_lba, sectors)."""
    entry_size, num_entries = 128, max(len(entries), 8)
    entry_lba = 2
    header = bytearray(b"\x00" * sector_size)
    header[0:8] = b"EFI PART"
    struct.pack_into("<I", header, 8, 0x00010000)
    struct.pack_into("<I", header, 12, 92)
    struct.pack_into("<QII", header, 72, entry_lba, num_entries, entry_size)

    table = bytearray(b"\x00" * (num_entries * entry_size))
    for i, (name, start, count) in enumerate(entries):
        off = i * entry_size
        table[off : off + 16] = b"\x11" * 16          # type guid (non-null)
        table[off + 16 : off + 32] = bytes([i + 1]) * 16
        struct.pack_into("<QQ", table, off + 32, start, start + count - 1)
        encoded = name.encode("utf-16-le")[:70]
        table[off + 56 : off + 56 + len(encoded)] = encoded

    out = bytearray(b"\x00" * sector_size)            # protective MBR
    out += header
    out += b"\x00" * ((entry_lba - 2) * sector_size)
    out += table
    return bytes(out)


# --- protobuf / OTA payload builders -----------------------------------------

def _varint(value: int) -> bytes:
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        out.append(byte | (0x80 if value else 0))
        if not value:
            return bytes(out)


def pb_varint(number: int, value: int) -> bytes:
    return _varint(number << 3 | 0) + _varint(value)


def pb_bytes(number: int, value: bytes) -> bytes:
    return _varint(number << 3 | 2) + _varint(len(value)) + value


def _extent(start_block: int, num_blocks: int) -> bytes:
    return pb_varint(1, start_block) + pb_varint(2, num_blocks)


def build_payload(partitions: dict[str, tuple[bytes, str]], block_size: int = 4096) -> bytes:
    """Build a synthetic full OTA payload.

    ``partitions`` maps name -> (image bytes, op kind) where op kind is one of
    "replace", "bz", "xz", "zero", or "delta" (to simulate an incremental OTA).
    """
    import bz2
    import hashlib
    import lzma
    import struct

    blobs = bytearray()
    part_msgs = []

    for name, (image, kind) in partitions.items():
        padded = image + b"\x00" * ((-len(image)) % block_size)
        num_blocks = len(padded) // block_size

        if kind == "zero":
            payload_data, op_type = b"", 6
        elif kind == "bz":
            payload_data, op_type = bz2.compress(padded), 1
        elif kind == "xz":
            payload_data, op_type = lzma.compress(padded), 8
        elif kind == "delta":
            payload_data, op_type = b"\x00" * 8, 3        # BSDIFF
        else:
            payload_data, op_type = padded, 0

        offset = len(blobs)
        blobs += payload_data

        op = (
            pb_varint(1, op_type)
            + pb_varint(2, offset)
            + pb_varint(3, len(payload_data))
            + pb_bytes(6, _extent(0, num_blocks))
        )
        info = pb_varint(1, len(image)) + pb_bytes(2, hashlib.sha256(image).digest())
        part_msgs.append(
            pb_bytes(1, name.encode()) + pb_bytes(8, op) + pb_bytes(9, info)
        )

    manifest = pb_varint(3, block_size) + b"".join(pb_bytes(13, m) for m in part_msgs)
    header = b"CrAU" + struct.pack(">QQ", 2, len(manifest)) + struct.pack(">I", 0)
    return header + manifest + bytes(blobs)
