"""Tests for Unicode shadowing detection."""

from policyforge.trust.shadowing import canonicalize, shadows


class TestCanonicalize:
    def test_nfkc_composes_decomposed_forms(self):
        # "é" as U+00E9 vs "e" + U+0301 (combining acute)
        composed = "fil\u00e9"
        decomposed = "file\u0301"
        assert canonicalize(composed) == canonicalize(decomposed)

    def test_compatibility_fold(self):
        # Fullwidth "A" (U+FF21) should fold to ASCII "A" under NFKC
        assert canonicalize("\uff21") == canonicalize("A")

    def test_homoglyph_cyrillic_a_folds_to_latin_a(self):
        # U+0430 CYRILLIC SMALL LETTER A vs U+0061 LATIN SMALL LETTER A
        assert canonicalize("\u0430pi") == canonicalize("api")

    def test_homoglyph_cyrillic_o_folds(self):
        # U+043E CYRILLIC SMALL LETTER O vs U+006F LATIN SMALL LETTER O
        assert canonicalize("f\u043eo") == canonicalize("foo")

    def test_homoglyph_greek_o_folds(self):
        # U+03BF GREEK SMALL LETTER OMICRON vs U+006F
        assert canonicalize("f\u03bfo") == canonicalize("foo")

    def test_case_is_folded_for_comparison(self):
        # By default, we fold to lowercase for comparison
        assert canonicalize("Foo") == canonicalize("foo")

    def test_non_homoglyph_chars_unchanged(self):
        assert canonicalize("plain_name") == "plain_name"

    def test_casefold_handles_eszett(self):
        # str.lower leaves U+00DF (ß) unchanged; str.casefold expands to "ss".
        # This test pins the stricter behavior so a regression to .lower() fails.
        assert canonicalize("stra\u00dfe") == canonicalize("strasse")


class TestShadows:
    def test_same_name_does_not_shadow_itself(self):
        # Two *equal* names aren't a shadowing pair
        assert shadows("send_email", "send_email") is False

    def test_cyrillic_homoglyph_shadows(self):
        # Cyrillic "ѕ" (U+0455) vs Latin "s"
        assert shadows("\u0455end_email", "send_email") is True

    def test_different_names_do_not_shadow(self):
        assert shadows("send_email", "read_file") is False

    def test_nfkc_collision_shadows(self):
        assert shadows("fil\u00e9", "file\u0301") is True

    def test_fullwidth_shadows_ascii(self):
        assert shadows("\uff41pi", "api") is True

    def test_cyrillic_t_shadows_latin(self):
        # U+0442 CYRILLIC SMALL LETTER TE vs U+0074 LATIN SMALL LETTER T
        assert shadows("dele\u0442_email", "delet_email") is True
