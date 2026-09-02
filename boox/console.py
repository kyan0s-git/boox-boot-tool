"""Shared console output.

Kept in one place so that every command speaks with the same voice, and so the
danger-tier styling is impossible to get wrong by accident.
"""

from __future__ import annotations

import os
import sys

from rich.console import Console
from rich.panel import Panel
from rich.theme import Theme

_THEME = Theme(
    {
        "ok": "bold green",
        "warn": "bold yellow",
        "danger": "bold red",
        "step": "bold cyan",
        "dim": "dim",
        "hash": "magenta",
    }
)

console = Console(theme=_THEME, stderr=False, highlight=False)
err_console = Console(theme=_THEME, stderr=True, highlight=False)


def step(message: str) -> None:
    console.print(f"[step]==>[/step] {message}")


def ok(message: str) -> None:
    console.print(f"[ok]  ok[/ok]  {message}")


def warn(message: str) -> None:
    console.print(f"[warn]warn[/warn]  {message}")


def fail(message: str) -> None:
    err_console.print(f"[danger]FAIL[/danger]  {message}")


def info(message: str) -> None:
    console.print(f"[dim]      {message}[/dim]")


def banner(title: str, body: str, style: str = "warn") -> None:
    console.print(Panel(body, title=title, border_style=style, expand=False))


def confirm_phrase(prompt: str, phrase: str, *, assume_yes: bool = False) -> bool:
    """Require the user to type ``phrase`` exactly.

    Used as the last gate in front of dangerous writes.  ``assume_yes`` exists
    for non-interactive use, but callers must only pass it when the user has
    supplied the phrase on the command line themselves.
    """
    if assume_yes:
        return True
    if not sys.stdin.isatty():
        raise RuntimeError("refusing to proceed: confirmation required but stdin is not a terminal")
    console.print(prompt)
    console.print(f"Type exactly [danger]{phrase}[/danger] to continue, anything else to abort.")
    try:
        answer = input("> ").strip()
    except (EOFError, KeyboardInterrupt):
        return False
    return answer == phrase


def is_quiet() -> bool:
    return bool(os.environ.get("BOOX_QUIET"))
