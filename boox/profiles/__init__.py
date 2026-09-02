"""Declarative per-device knowledge."""

from boox.profiles.schema import (
    LoaderCandidate,
    Profile,
    available,
    load,
    load_all,
    load_file,
    match_adb_model,
)

__all__ = [
    "LoaderCandidate",
    "Profile",
    "available",
    "load",
    "load_all",
    "load_file",
    "match_adb_model",
]
