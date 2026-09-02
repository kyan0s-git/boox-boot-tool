"""The golden firmware reference.

An official, decrypted firmware package gives us stock partition images that did
not come from the tablet in front of us.  That independence is the point: if the
device's own backup captured an already-broken state, the backup alone cannot
tell us so.  Two sources that agree is a much stronger position than one.

The pipeline is: update.upx -> AES-CFB decrypt -> zip -> payload.bin -> images.
"""

from __future__ import annotations

import json
import time
import zipfile
from dataclasses import dataclass
from pathlib import Path

from boox import __version__
from boox.console import info, ok, step
from boox.errors import FirmwareError
from boox.firmware import keys as keys_mod
from boox.firmware import onyx_api
from boox.firmware.payload import Payload
from boox.firmware.upx import UpxDecryptor
from boox.safety.tiers import base_name
from boox.safety.verify import Reference
from boox.util import human_size, sha256_file, short

MANIFEST_NAME = "golden.json"
SCHEMA_VERSION = 1

# The images worth extracting: everything the tool might ever write, plus vbmeta
# so we can report whether stock has verification disabled.
WANTED = (
    "boot", "init_boot", "vendor_boot", "recovery", "dtbo",
    "vbmeta", "vbmeta_system", "vbmeta_vendor",
)


@dataclass
class GoldenFirmware:
    root: Path
    manifest: dict

    @classmethod
    def load(cls, root: Path) -> "GoldenFirmware":
        root = Path(root)
        path = root / MANIFEST_NAME
        if not path.is_file():
            raise FirmwareError(f"{root} holds no extracted firmware ({MANIFEST_NAME} missing)")
        return cls(root=root, manifest=json.loads(path.read_text(encoding="utf-8")))

    @property
    def version(self) -> str:
        return str(self.manifest.get("version", "unknown"))

    @property
    def model(self) -> str:
        return str(self.manifest.get("model", "unknown"))

    def images(self) -> dict[str, dict]:
        return self.manifest.get("images", {})

    def image(self, partition: str) -> Path | None:
        """Look up by base name, so ``boot_a`` finds the payload's ``boot``."""
        entry = self.images().get(base_name(partition))
        if not entry:
            return None
        path = self.root / entry["file"]
        return path if path.is_file() else None

    def reference(self, partition: str) -> Reference | None:
        path = self.image(partition)
        if path is None:
            return None
        return Reference(f"stock firmware {base_name(partition)}.img ({self.version})",
                         path.read_bytes())

    def verify(self) -> list[str]:
        problems = []
        for name, entry in sorted(self.images().items()):
            path = self.root / entry["file"]
            if not path.is_file():
                problems.append(f"{name}: missing")
            elif sha256_file(path) != entry["sha256"]:
                problems.append(f"{name}: hash does not match the manifest")
        return problems

    def describe(self) -> str:
        return f"{self.model} {self.version}: {', '.join(sorted(self.images()))}"


def _extract_payload(zip_path: Path, dest: Path) -> Path:
    with zipfile.ZipFile(zip_path) as archive:
        names = archive.namelist()
        candidates = [n for n in names if n.endswith("payload.bin")]
        if not candidates:
            raise FirmwareError(
                "the decrypted firmware package contains no payload.bin",
                remedy=(
                    "This may be an older non-A/B package. Its images are in the zip "
                    f"directly; it contains: {', '.join(names[:20])}"
                ),
            )
        dest.parent.mkdir(parents=True, exist_ok=True)
        with archive.open(candidates[0]) as src, open(dest, "wb") as out:
            while chunk := src.read(1 << 20):
                out.write(chunk)
    return dest


def acquire(
    model: str,
    workdir: Path,
    *,
    upx: Path | None = None,
    key: str | None = None,
    iv: str | None = None,
    keys_csv: Path | None = None,
    version: str | None = None,
    wanted: tuple[str, ...] = WANTED,
) -> GoldenFirmware:
    """Produce stock partition images for ``model``, downloading if needed."""
    workdir = Path(workdir)
    workdir.mkdir(parents=True, exist_ok=True)

    release = None
    if upx is None:
        step(f"asking Onyx for the latest firmware for {model}")
        release = onyx_api.query_latest(model)
        info(release.describe())
        upx = workdir / "update.upx"
        if upx.is_file():
            info(f"reusing the package already downloaded at {upx}")
        else:
            onyx_api.download(release, upx)
        version = version or release.version
    upx = Path(upx)
    if not upx.is_file():
        raise FirmwareError(f"firmware package not found: {upx}")

    if key and iv:
        pair_source = "supplied on the command line"
    else:
        pair = keys_mod.find(model, csv_path=keys_csv)
        key, iv, pair_source = pair.key, pair.iv, pair.source

    step(f"decrypting {upx.name} ({human_size(upx.stat().st_size)}) using keys from {pair_source}")
    update_zip = workdir / "update.zip"
    UpxDecryptor(key, iv).decrypt(upx, update_zip)

    payload_path = _extract_payload(update_zip, workdir / "payload.bin")
    payload = Payload(payload_path)
    info(f"payload contains: {', '.join(payload.names())}")

    images_dir = workdir / "images"
    images_dir.mkdir(parents=True, exist_ok=True)
    images: dict[str, dict] = {}
    for name in wanted:
        if name not in payload.partitions:
            continue
        entry = payload.require(name)
        if not entry.is_full:
            info(f"{name}: skipped, it uses delta operations (incremental OTA)")
            continue
        out = payload.extract(name, images_dir / f"{name}.img")
        digest = sha256_file(out)
        images[name] = {"file": f"images/{out.name}", "sha256": digest, "size": out.stat().st_size}
        info(f"{name}: {human_size(out.stat().st_size)}  {short(digest)}")

    if not images:
        raise FirmwareError(
            "no usable stock images could be extracted",
            remedy=(
                "If this was an incremental OTA, fetch the full package instead. "
                f"The payload offered: {', '.join(payload.names())}"
            ),
        )

    manifest = {
        "schema": SCHEMA_VERSION,
        "tool_version": __version__,
        "created": time.time(),
        "model": model,
        "version": version or "unknown",
        "source_upx": str(upx),
        "source_url": release.url if release else None,
        "images": images,
    }
    (workdir / MANIFEST_NAME).write_text(json.dumps(manifest, indent=2, sort_keys=True))

    golden = GoldenFirmware(root=workdir, manifest=manifest)
    problems = golden.verify()
    if problems:
        raise FirmwareError("extracted images failed their own hash check:\n  " + "\n  ".join(problems))
    ok(f"stock firmware ready: {golden.describe()}")
    return golden
