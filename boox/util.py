"""Small shared helpers."""

from __future__ import annotations

import hashlib
import shutil
from pathlib import Path

CHUNK = 1024 * 1024


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        while chunk := fh.read(CHUNK):
            digest.update(chunk)
    return digest.hexdigest()


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def human_size(num: int) -> str:
    value = float(num)
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if abs(value) < 1024 or unit == "TiB":
            return f"{value:.0f} {unit}" if unit == "B" else f"{value:.1f} {unit}"
        value /= 1024
    return f"{value:.1f} TiB"


def free_space(path: Path) -> int:
    target = path
    while not target.exists() and target.parent != target:
        target = target.parent
    return shutil.disk_usage(target).free


def short(digest: str | None, width: int = 12) -> str:
    return (digest or "?")[:width]
