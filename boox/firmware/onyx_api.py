"""Onyx's firmware update endpoint.

The device itself asks this endpoint what the latest build is.  We ask the same
question, but deliberately send an empty ``deviceMAC`` and ``fingerprint``:
this tool exists partly to stop the tablet reporting its identifiers to Onyx,
so it would be incoherent for the tool to report them on the user's behalf.

The endpoint is plain HTTP with no certificate to pin, so treat the response as
untrusted input -- which is why the download is checked against the payload
manifest's own hashes before any image from it is trusted as a reference.
"""

from __future__ import annotations

import json
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from boox.errors import FirmwareError

DEFAULT_ENDPOINT = "http://en-data.onyx-international.cn/api/firmware/update"
USER_AGENT = "Mozilla/5.0 (Linux; Android 13)"


@dataclass(frozen=True)
class FirmwareRelease:
    model: str
    version: str
    build_number: int
    url: str
    size: int | None
    md5: str | None
    changelog: str = ""
    raw: dict | None = None

    def describe(self) -> str:
        size = f", {self.size} bytes" if self.size else ""
        return f"{self.model} {self.version} (build {self.build_number}){size}"


def _first(data: dict, *keys, default=None):
    for key in keys:
        if key in data and data[key] not in (None, ""):
            return data[key]
    return default


def query_latest(
    model: str,
    *,
    build_number: int = 0,
    lang: str = "en_US",
    endpoint: str = DEFAULT_ENDPOINT,
    timeout: int = 60,
) -> FirmwareRelease:
    """Ask Onyx for the newest firmware for ``model``.

    ``build_number=0`` means "tell me about the newest build regardless of what
    I am running", which is what we want for a golden reference.
    """
    where = {
        "buildNumber": build_number,
        "buildType": "user",
        "deviceMAC": "",       # deliberately empty; see module docstring
        "lang": lang,
        "model": model,
        "submodel": "",
        "fingerprint": "",
    }
    url = f"{endpoint}?where={urllib.parse.quote(json.dumps(where, separators=(',', ':')))}"
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310
            body = response.read()
    except Exception as exc:
        raise FirmwareError(
            f"could not reach the Onyx update server: {exc}",
            remedy=(
                "Check your network, or download the update.upx yourself and pass it "
                "with 'boox firmware decrypt --upx <file>'."
            ),
        ) from exc

    try:
        data = json.loads(body.decode("utf-8", "replace"))
    except json.JSONDecodeError as exc:
        raise FirmwareError(f"the update server returned something that is not JSON: {exc}") from exc

    payload = data.get("data") if isinstance(data.get("data"), dict) else data
    if not isinstance(payload, dict):
        raise FirmwareError(f"unexpected response shape from the update server: {data!r}")

    urls = _first(payload, "downloadUrlList", "downloadUrls", default=None)
    if isinstance(urls, list) and urls:
        download_url = urls[0]
    else:
        download_url = _first(payload, "url", "downloadUrl", default=None)
    if not download_url:
        raise FirmwareError(
            f"no firmware download URL for model {model!r}",
            remedy=(
                "Onyx may not publish this model on the international endpoint. "
                "Download update.upx by hand and use 'boox firmware decrypt --upx'."
            ),
        )

    return FirmwareRelease(
        model=model,
        version=str(_first(payload, "versionName", "version", default="unknown")),
        build_number=int(_first(payload, "buildNumber", "versionCode", default=0) or 0),
        url=str(download_url),
        size=_first(payload, "size", "fileSize"),
        md5=_first(payload, "md5", "fileMd5"),
        changelog=str(_first(payload, "changelog", "desc", default="") or ""),
        raw=payload,
    )


def download(
    release: FirmwareRelease,
    dest: Path,
    *,
    timeout: int = 120,
    progress: Callable[[int, int | None], None] | None = None,
) -> Path:
    """Download a firmware package, verifying its MD5 when the server gave one."""
    import hashlib

    dest = Path(dest)
    dest.parent.mkdir(parents=True, exist_ok=True)
    tmp = dest.with_suffix(dest.suffix + ".partial")
    digest = hashlib.md5()  # noqa: S324 - integrity only; Onyx publishes MD5
    total = release.size if isinstance(release.size, int) else None
    seen = 0

    request = urllib.request.Request(release.url, headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response, open(tmp, "wb") as fh:  # noqa: S310
            while chunk := response.read(1 << 20):
                fh.write(chunk)
                digest.update(chunk)
                seen += len(chunk)
                if progress:
                    progress(seen, total)
    except Exception as exc:
        tmp.unlink(missing_ok=True)
        raise FirmwareError(f"firmware download failed: {exc}") from exc

    if release.md5 and digest.hexdigest().lower() != str(release.md5).lower():
        tmp.unlink(missing_ok=True)
        raise FirmwareError(
            f"downloaded firmware MD5 is {digest.hexdigest()}, server said {release.md5}",
            remedy="The download was corrupted or tampered with. Try again.",
        )
    tmp.replace(dest)
    return dest
