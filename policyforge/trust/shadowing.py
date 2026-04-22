"""Unicode shadowing detection for tool names.

``canonicalize`` folds a name through:
  1. NFKC normalization (handles decomposed forms + fullwidth + ligatures).
  2. A minimum-viable homoglyph map (Cyrillic/Greek -> Latin for the most
     commonly-confused letters).
  3. ASCII-lowercasing (case-insensitive comparison).

``shadows(a, b)`` returns True when two *distinct* raw names canonicalize
to the same value.  Equal raw names do not count as shadowing.
"""

from __future__ import annotations

import unicodedata

# Handcrafted homoglyph map — Latin targets for commonly-abused lookalikes.
# Documented as minimum-viable; a full ICU confusables table can replace
# this later without changing the public API.
_HOMOGLYPHS: dict[str, str] = {
    # Cyrillic lowercase -> Latin lowercase
    "\u0430": "a",  # а
    "\u0435": "e",  # е
    "\u043e": "o",  # о
    "\u0440": "p",  # р
    "\u0441": "c",  # с
    "\u0443": "y",  # у
    "\u0445": "x",  # х
    "\u0455": "s",  # ѕ
    "\u0456": "i",  # і
    "\u0458": "j",  # ј
    "\u04cf": "l",  # ӏ
    # Cyrillic uppercase -> Latin uppercase (folded later to lower)
    "\u0410": "A",
    "\u0415": "E",
    "\u041e": "O",
    "\u0420": "P",
    "\u0421": "C",
    "\u0425": "X",
    # Greek lowercase -> Latin lowercase
    "\u03bf": "o",  # ο
    "\u03b1": "a",  # α
    "\u03c1": "p",  # ρ
    "\u03c5": "u",  # υ
    "\u03bd": "v",  # ν
    # Greek uppercase
    "\u0391": "A",
    "\u0395": "E",
    "\u039f": "O",
    "\u03a1": "P",
}


def _fold_homoglyphs(text: str) -> str:
    """Apply homoglyph substitution to a normalized string."""
    return "".join(_HOMOGLYPHS.get(ch, ch) for ch in text)


def canonicalize(name: str) -> str:
    """Fold a name to a canonical form for shadowing comparison.

    NFKC -> homoglyph fold -> ASCII-lowercase.
    """
    nfkc = unicodedata.normalize("NFKC", name)
    folded = _fold_homoglyphs(nfkc)
    return folded.lower()


def shadows(a: str, b: str) -> bool:
    """Return True if two *distinct* raw names canonicalize to the same form."""
    if a == b:
        return False
    return canonicalize(a) == canonicalize(b)
