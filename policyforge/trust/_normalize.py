"""Shared NFKC normalization helper used across the trust subsystem."""

from __future__ import annotations

import unicodedata


def nfkc(name: str) -> str:
    """Return the NFKC-normalized form of ``name``."""
    return unicodedata.normalize("NFKC", name)
