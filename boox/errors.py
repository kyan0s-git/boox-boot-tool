"""Exception hierarchy.

Every failure path in this tool is expected to raise one of these rather than
letting a bare exception escape.  ``BooxError`` carries an optional ``remedy``
string because most failures here have a specific, actionable next step and the
user is usually holding a half-flashed tablet when they read it.
"""

from __future__ import annotations


class BooxError(Exception):
    """Base class for all errors raised by this tool."""

    def __init__(self, message: str, remedy: str | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.remedy = remedy

    def __str__(self) -> str:  # pragma: no cover - trivial
        if self.remedy:
            return f"{self.message}\n  -> {self.remedy}"
        return self.message


class ProfileError(BooxError):
    """A device profile is missing, malformed, or does not match the device."""


class TransportError(BooxError):
    """Talking to the device failed (adb or EDL)."""


class EdlError(TransportError):
    """An EDL/Firehose operation failed."""


class AdbError(TransportError):
    """An adb operation failed."""


class ImageError(BooxError):
    """A partition image could not be parsed or is structurally invalid."""


class VerificationError(BooxError):
    """An image failed verification. Nothing was written."""


class SafetyError(BooxError):
    """A safety gate refused to let an operation proceed."""


class PreflightError(SafetyError):
    """The pre-write safety checks did not all pass."""


class BackupError(SafetyError):
    """A backup could not be taken, verified, or restored."""


class FirmwareError(BooxError):
    """Official firmware could not be fetched, decrypted, or extracted."""
