"""Subprocess helper.

Every external command this tool runs goes through here so that failures look
the same, output can be captured for a bug report, and a dry run can print the
command instead of running it.
"""

from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

from boox.console import info, is_quiet


@dataclass(frozen=True)
class Result:
    argv: list[str]
    returncode: int
    stdout: str
    stderr: str

    @property
    def ok(self) -> bool:
        return self.returncode == 0

    @property
    def output(self) -> str:
        """stdout and stderr combined, for tools that mix the two."""
        return f"{self.stdout}\n{self.stderr}".strip()

    def tail(self, lines: int = 12) -> str:
        return "\n".join(self.output.splitlines()[-lines:])


def which(*candidates: str) -> str | None:
    for candidate in candidates:
        found = shutil.which(candidate)
        if found:
            return found
    return None


def run(
    argv: list[str],
    *,
    timeout: int = 600,
    cwd: Path | None = None,
    check: bool = False,
    echo: bool = True,
) -> Result:
    if echo and not is_quiet():
        info("$ " + " ".join(argv))
    try:
        proc = subprocess.run(
            argv,
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=str(cwd) if cwd else None,
            errors="replace",
        )
    except FileNotFoundError as exc:
        raise FileNotFoundError(f"{argv[0]}: not found on PATH") from exc
    except subprocess.TimeoutExpired as exc:
        raise TimeoutError(f"{argv[0]} timed out after {timeout}s") from exc

    result = Result(argv, proc.returncode, proc.stdout or "", proc.stderr or "")
    if check and not result.ok:
        raise RuntimeError(f"{argv[0]} exited {result.returncode}:\n{result.tail()}")
    return result
