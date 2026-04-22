"""Unicode shadowing detection for tool names.

``canonicalize`` folds a name through:
  1. NFKC normalization (handles decomposed forms + fullwidth + ligatures).
  2. A minimum-viable homoglyph map (Cyrillic/Greek -> Latin for the most
     commonly-confused letters).
  3. Unicode case folding via str.casefold (handles ß, Turkish dotless i, etc.).

``shadows(a, b)`` returns True when two *distinct* raw names canonicalize
to the same value.  Equal raw names do not count as shadowing.
"""

from __future__ import annotations

import unicodedata

# Digit/letter confusables (e.g., "0" vs "O", "1" vs "l"/"I") are intentionally
# out of scope for this minimum-viable table — their visual similarity varies
# too widely by font to justify a security-grade fold. A future ICU-backed
# replacement can add them if needed.

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
    "\u0442": "t",  # т
    "\u043a": "k",  # к
    "\u0432": "b",  # в
    "\u043c": "m",  # м
    "\u043d": "h",  # н
    # Cyrillic uppercase -> Latin uppercase (folded later to lower)
    "\u0410": "A",
    "\u0415": "E",
    "\u041e": "O",
    "\u0420": "P",
    "\u0421": "C",
    "\u0425": "X",
    "\u0412": "B",  # В
    "\u041d": "H",  # Н
    "\u041a": "K",  # К
    "\u041c": "M",  # М
    "\u0422": "T",  # Т
    # Greek lowercase -> Latin lowercase
    "\u03bf": "o",  # ο
    "\u03b1": "a",  # α
    "\u03c1": "p",  # ρ
    "\u03c5": "u",  # υ
    "\u03bd": "v",  # ν
    "\u03b9": "i",  # ι
    "\u03ba": "k",  # κ
    "\u03c4": "t",  # τ
    "\u03c7": "x",  # χ
    "\u03b2": "b",  # β
    "\u03bc": "u",  # μ
    # Greek uppercase
    "\u0391": "A",
    "\u0395": "E",
    "\u039f": "O",
    "\u03a1": "P",
    "\u0392": "B",  # Β
    "\u039c": "M",  # Μ
    "\u039d": "N",  # Ν
    "\u0399": "I",  # Ι
    "\u039a": "K",  # Κ
    "\u03a4": "T",  # Τ
    "\u03a7": "X",  # Χ
}


def _fold_homoglyphs(text: str) -> str:
    """Apply homoglyph substitution to a normalized string."""
    return "".join(_HOMOGLYPHS.get(ch, ch) for ch in text)


def canonicalize(name: str) -> str:
    """Fold a name to a canonical form for shadowing comparison.

    NFKC -> homoglyph fold -> Unicode case folding.
    """
    nfkc = unicodedata.normalize("NFKC", name)
    folded = _fold_homoglyphs(nfkc)
    return folded.casefold()


def shadows(a: str, b: str) -> bool:
    """Return True if two *distinct* raw names canonicalize to the same form."""
    if a == b:
        return False
    return canonicalize(a) == canonicalize(b)
