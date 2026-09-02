"""EDL (Qualcomm Sahara + Firehose) backends.

EDL is the only usable write channel on these devices, so this module is the
narrow waist that all partition traffic passes through.  It deliberately does
*not* implement Sahara/Firehose itself: it drives an existing, widely-tested
implementation as a subprocess.  Two are supported --  bkerler's Python ``edl``
and Renate's Windows ``edl.exe`` -- plus an in-process mock for tests.

Backends are intentionally dumb. They move bytes and report what happened.
Hashing, verification, journalling and refusal all live in :mod:`boox.safety`,
so that no backend can accidentally be a way around a safety check.
"""

from __future__ import annotations

import abc
import tempfile
from pathlib import Path

from boox.errors import EdlError
from boox.imaging.gpt import PartitionTable, parse_gpt_binary, parse_printgpt_text, parse_rawprogram_xml
from boox.transport import sahara
from boox.transport.proc import Result, run, which


class EdlBackend(abc.ABC):
    """Moves bytes to and from partitions. Makes no safety decisions."""

    name: str = "abstract"

    @abc.abstractmethod
    def identify(self) -> sahara.DeviceIdentity:
        """Complete a handshake and report what chip is on the other end."""

    @abc.abstractmethod
    def partition_table(self) -> PartitionTable:
        ...

    @abc.abstractmethod
    def read_partition(self, name: str, dest: Path) -> int:
        """Read a whole partition to ``dest``; returns bytes written."""

    @abc.abstractmethod
    def write_partition(self, name: str, src: Path) -> None:
        ...

    @abc.abstractmethod
    def erase_partition(self, name: str) -> None:
        ...

    @abc.abstractmethod
    def reset(self) -> None:
        """Reboot the device out of EDL."""

    def close(self) -> None:  # pragma: no cover - most backends need nothing
        return None


class EdlClientBackend(EdlBackend):
    """Drives bkerler's ``edl`` (edlclient), the cross-platform option."""

    name = "edlclient"

    def __init__(self, loader: Path, memory: str = "emmc", binary: str | None = None) -> None:
        self.loader = Path(loader)
        self.memory = memory
        self.binary = binary or which("edl", "edl.py")
        if not self.binary:
            raise EdlError(
                "the 'edl' command was not found on PATH",
                remedy="Install it with: pip install git+https://github.com/bkerler/edl",
            )
        if not self.loader.is_file():
            raise EdlError(
                f"loader file not found: {self.loader}",
                remedy="Run 'boox loader fetch' to download a candidate loader.",
            )
        self._banner: str = ""

    def _base(self) -> list[str]:
        return [self.binary, f"--loader={self.loader}", f"--memory={self.memory}"]

    def _run(self, args: list[str], *, timeout: int = 1800) -> Result:
        result = run(self._base() + args, timeout=timeout)
        if result.output:
            self._banner = result.output
        return result

    def identify(self) -> sahara.DeviceIdentity:
        result = self._run(["printgpt"], timeout=300)
        identity = sahara.parse(result.output)
        if not identity.known and not result.ok:
            raise EdlError(
                f"could not complete an EDL handshake:\n{result.tail()}",
                remedy=(
                    "Check the device really is in 9008 mode, that the loader matches "
                    "this SoC, and on Windows that the QDLoader driver is installed."
                ),
            )
        return identity

    def partition_table(self) -> PartitionTable:
        # Preferred: ask edl to dump the real GPT plus a rawprogram XML.
        with tempfile.TemporaryDirectory(prefix="boox-gpt-") as tmp:
            tmpdir = Path(tmp)
            result = self._run(["gpt", str(tmpdir)], timeout=600)
            table = self._table_from_dir(tmpdir)
            if table is not None:
                return table
            banner = result.output

        # Fall back to the printed table.
        result = self._run(["printgpt"], timeout=300)
        text = result.output or banner
        try:
            return parse_printgpt_text(text)
        except Exception as exc:
            raise EdlError(
                f"could not read the partition table: {exc}",
                remedy="Re-run with --debug and include the output in a bug report.",
            ) from exc

    @staticmethod
    def _table_from_dir(tmpdir: Path) -> PartitionTable | None:
        for candidate in sorted(tmpdir.glob("gpt-main*.bin")):
            try:
                return parse_gpt_binary(candidate.read_bytes())
            except Exception:
                continue
        xmls = {p.name: p.read_text(errors="replace") for p in sorted(tmpdir.glob("rawprogram*.xml"))}
        if xmls:
            try:
                return parse_rawprogram_xml(xmls)
            except Exception:
                return None
        return None

    def read_partition(self, name: str, dest: Path) -> int:
        dest.parent.mkdir(parents=True, exist_ok=True)
        result = self._run(["r", name, str(dest)])
        if not result.ok or not dest.exists() or dest.stat().st_size == 0:
            raise EdlError(
                f"reading partition {name} failed:\n{result.tail()}",
                remedy="A failed read is harmless; check the cable and retry.",
            )
        return dest.stat().st_size

    def write_partition(self, name: str, src: Path) -> None:
        result = self._run(["w", name, str(src)])
        if not result.ok:
            raise EdlError(
                f"writing partition {name} failed:\n{result.tail()}",
                remedy=(
                    "Do NOT reboot the device. Re-run the same write, and if it keeps "
                    "failing run 'boox rescue diagnose' to restore this partition."
                ),
            )

    def erase_partition(self, name: str) -> None:
        result = self._run(["e", name])
        if not result.ok:
            raise EdlError(f"erasing partition {name} failed:\n{result.tail()}")

    def reset(self) -> None:
        run([self.binary, "reset"], timeout=120)


class TemblastBackend(EdlBackend):
    """Drives Renate's Windows ``edl.exe``.

    Its switches take no space after the flag (``/lloader.bin``), and ``/u`` is
    required on UFS devices. Kept as an option because it is the tool most Boox
    guides on Windows assume.
    """

    name = "temblast"

    def __init__(self, loader: Path, memory: str = "emmc", binary: str | None = None) -> None:
        self.loader = Path(loader)
        self.memory = memory
        self.binary = binary or which("edl.exe", "edl")
        if not self.binary:
            raise EdlError("edl.exe was not found on PATH")
        self._loaded = False

    def _flags(self) -> list[str]:
        return ["/u"] if self.memory == "ufs" else []

    def _ensure_loader(self) -> str:
        if not self._loaded:
            result = run([self.binary, f"/l{self.loader}"], timeout=300)
            if "Firehose" not in result.output and not result.ok:
                raise EdlError(f"loader was not accepted:\n{result.tail()}")
            self._loaded = True
            return result.output
        return ""

    def identify(self) -> sahara.DeviceIdentity:
        return sahara.parse(self._ensure_loader())

    def partition_table(self) -> PartitionTable:
        self._ensure_loader()
        result = run([self.binary, *self._flags(), "/g"], timeout=300)
        return parse_printgpt_text(result.output)

    def read_partition(self, name: str, dest: Path) -> int:
        self._ensure_loader()
        dest.parent.mkdir(parents=True, exist_ok=True)
        result = run([self.binary, *self._flags(), "/r", f"/p{name}", str(dest)], timeout=1800)
        if not result.ok or not dest.exists():
            raise EdlError(f"reading partition {name} failed:\n{result.tail()}")
        return dest.stat().st_size

    def write_partition(self, name: str, src: Path) -> None:
        self._ensure_loader()
        result = run([self.binary, *self._flags(), "/w", f"/p{name}", str(src)], timeout=1800)
        if not result.ok:
            raise EdlError(
                f"writing partition {name} failed:\n{result.tail()}",
                remedy=(
                    "Do NOT reboot. Retry, then run 'boox rescue diagnose' if it "
                    "keeps failing."
                ),
            )

    def erase_partition(self, name: str) -> None:
        self._ensure_loader()
        result = run([self.binary, *self._flags(), "/e", f"/p{name}"], timeout=600)
        if not result.ok:
            raise EdlError(f"erasing partition {name} failed:\n{result.tail()}")

    def reset(self) -> None:
        run([self.binary, "/z"], timeout=120)
