"""Lookup of per-model ``update.upx`` decryption keys.

The key database is not distributed with this tool.  It is community-recovered
data maintained at https://github.com/Hagb/decryptBooxUpdateUpx, which ships no
licence, so we point at it rather than copying it.  Supply the CSV yourself, let
``boox firmware keys --fetch`` download it, or pass --key/--iv directly.
"""

from __future__ import annotations

import csv
import os
import urllib.request
from dataclasses import dataclass
from pathlib import Path

from boox.errors import FirmwareError

UPSTREAM_CSV = (
    "https://raw.githubusercontent.com/Hagb/decryptBooxUpdateUpx/master/BooxKeys.csv"
)
ENV_VAR = "BOOX_KEYS_CSV"
FILENAME = "BooxKeys.csv"


@dataclass(frozen=True)
class KeyPair:
    model: str
    key: str
    iv: str
    source: str


def search_paths(extra: Path | None = None) -> list[Path]:
    paths: list[Path] = []
    if extra:
        paths.append(Path(extra))
    if env := os.environ.get(ENV_VAR):
        paths.append(Path(env))
    paths.append(Path.cwd() / FILENAME)
    paths.append(Path.home() / ".config" / "boox" / FILENAME)
    return paths


def load_csv(path: Path) -> dict[str, KeyPair]:
    out: dict[str, KeyPair] = {}
    with open(path, newline="", encoding="utf-8") as fh:
        for row in csv.reader(fh):
            if len(row) < 4 or row[0].strip().lower() == "name":
                continue
            name, model, key, iv = (c.strip() for c in row[:4])
            pair = KeyPair(model=model or name, key=key, iv=iv, source=str(path))
            for alias in {name, model}:
                if alias:
                    out[alias.lower()] = pair
    return out


def find(model: str, *, csv_path: Path | None = None) -> KeyPair:
    """Find the key/IV for a model, searching the usual locations."""
    tried: list[str] = []
    for path in search_paths(csv_path):
        if not path.is_file():
            tried.append(f"{path} (not found)")
            continue
        table = load_csv(path)
        pair = table.get(model.strip().lower())
        if pair:
            return pair
        tried.append(f"{path} ({len(table)} models, none named {model!r})")
    raise FirmwareError(
        f"no decryption key found for model {model!r}",
        remedy=(
            "Run 'boox firmware keys --fetch' to download the community key database, "
            "or pass --key/--iv directly.\nSearched:\n  " + "\n  ".join(tried)
        ),
    )


def fetch(dest: Path | None = None, *, url: str = UPSTREAM_CSV, timeout: int = 60) -> Path:
    """Download the community key database."""
    dest = Path(dest) if dest else (Path.home() / ".config" / "boox" / FILENAME)
    dest.parent.mkdir(parents=True, exist_ok=True)
    try:
        with urllib.request.urlopen(url, timeout=timeout) as response:  # noqa: S310
            body = response.read()
    except Exception as exc:
        raise FirmwareError(
            f"could not download the key database: {exc}",
            remedy=f"Download {url} by hand and save it to {dest}.",
        ) from exc
    text = body.decode("utf-8", "replace")
    if "Key" not in text.splitlines()[0]:
        raise FirmwareError(f"{url} did not return a key CSV")
    dest.write_text(text, encoding="utf-8")
    return dest
