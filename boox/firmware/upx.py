"""Decryption of Onyx's ``update.upx`` firmware packages.

The scheme is AES-128 in CFB mode with a full 128-bit segment size, using a
per-model key and IV.  The plaintext is an ordinary zip, so a correct key is
self-evident: the first four bytes decrypt to the zip magic.  A wrong key fails
immediately rather than producing plausible garbage.

We do not ship the key database. Keys are per model and were recovered by the
community (see https://github.com/Hagb/decryptBooxUpdateUpx); this tool looks
for a ``BooxKeys.csv`` you supply or fetch, or takes a key and IV directly.
"""

from __future__ import annotations

from pathlib import Path
from typing import BinaryIO, Callable

from boox.errors import FirmwareError

ZIP_MAGIC = b"PK\x03\x04"
BLOCK = 1 << 16  # must be a multiple of the 16-byte AES block


def _make_cipher(key: bytes, iv: bytes) -> Callable[[bytes], bytes]:
    """Return a stateful CFB-128 decrypt function, using whichever crypto lib is present."""
    try:
        try:
            from Cryptodome.Cipher import AES  # type: ignore[import-not-found]
        except ImportError:
            from Crypto.Cipher import AES  # type: ignore[import-not-found]
        cipher = AES.new(key, AES.MODE_CFB, iv=iv, segment_size=128)
        return cipher.decrypt
    except ImportError:
        pass

    try:
        from cryptography.hazmat.primitives.ciphers import (  # type: ignore[import-not-found]
            Cipher, algorithms, modes,
        )

        decryptor = Cipher(algorithms.AES(key), modes.CFB(iv)).decryptor()
        return decryptor.update
    except ImportError as exc:
        raise FirmwareError(
            "no AES implementation is available",
            remedy="Install one:  pip install pycryptodome   (or 'cryptography')",
        ) from exc


class UpxDecryptor:
    def __init__(self, key_hex: str, iv_hex: str) -> None:
        try:
            self.key = bytes.fromhex(key_hex.strip())
            self.iv = bytes.fromhex(iv_hex.strip())
        except ValueError as exc:
            raise FirmwareError(f"key and IV must be hex strings: {exc}") from exc
        if len(self.key) not in (16, 24, 32):
            raise FirmwareError(f"key must be 16, 24 or 32 bytes, got {len(self.key)}")
        if len(self.iv) != 16:
            raise FirmwareError(f"IV must be 16 bytes, got {len(self.iv)}")

    def decrypt_stream(self, src: BinaryIO, dst: BinaryIO) -> int:
        decrypt = _make_cipher(self.key, self.iv)
        written = 0
        first = True
        while chunk := src.read(BLOCK):
            plain = decrypt(chunk)
            if first:
                if not plain.startswith(ZIP_MAGIC):
                    raise FirmwareError(
                        "decryption produced something that is not a zip archive",
                        remedy=(
                            "The key/IV are for a different model, or this is not an "
                            "update.upx. Check the model name against BooxKeys.csv."
                        ),
                    )
                first = False
            dst.write(plain)
            written += len(plain)
        if first:
            raise FirmwareError("the input file is empty")
        return written

    def decrypt(self, src: Path, dest: Path) -> Path:
        src, dest = Path(src), Path(dest)
        dest.parent.mkdir(parents=True, exist_ok=True)
        # Decrypt to a temporary name so a failure never leaves a half-written
        # file that looks like a usable firmware package.
        tmp = dest.with_suffix(dest.suffix + ".partial")
        try:
            with open(src, "rb") as fh_in, open(tmp, "wb") as fh_out:
                self.decrypt_stream(fh_in, fh_out)
            tmp.replace(dest)
        finally:
            tmp.unlink(missing_ok=True)
        return dest
