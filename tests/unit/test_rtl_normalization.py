"""Tests for RTL/bidi Unicode control character normalization."""

from aiRail.normalization.normalizer import TextNormalizer

# U+202E RIGHT-TO-LEFT OVERRIDE
RLO = "\u202e"
# U+202D LEFT-TO-RIGHT OVERRIDE
LRO = "\u202d"
# U+200F RIGHT-TO-LEFT MARK
RLM = "\u200f"
# U+2066 LEFT-TO-RIGHT ISOLATE
LRI = "\u2066"
# U+2069 POP DIRECTIONAL ISOLATE
PDI = "\u2069"
# U+061C ARABIC LETTER MARK
ALM = "\u061c"


class TestBidiNormalization:
    def test_strips_rlo_character(self):
        normalizer = TextNormalizer()
        text = f"Hello {RLO}noitcejni tpmorp"
        result = normalizer.normalize(text)
        assert RLO not in result.normalized
        assert "bidi_control_chars" in result.signals

    def test_strips_rlm_character(self):
        normalizer = TextNormalizer()
        text = f"normal text {RLM} more text"
        result = normalizer.normalize(text)
        assert RLM not in result.normalized
        assert "bidi_control_chars" in result.signals

    def test_strips_lri_pdi_pair(self):
        normalizer = TextNormalizer()
        text = f"{LRI}injected content{PDI}"
        result = normalizer.normalize(text)
        assert LRI not in result.normalized
        assert PDI not in result.normalized
        assert "bidi_control_chars" in result.signals

    def test_strips_arabic_letter_mark(self):
        normalizer = TextNormalizer()
        text = f"text {ALM} more"
        result = normalizer.normalize(text)
        assert ALM not in result.normalized
        assert "bidi_control_chars" in result.signals

    def test_clean_text_has_no_bidi_signal(self):
        normalizer = TextNormalizer()
        result = normalizer.normalize("Hello, world! This is normal text.")
        assert "bidi_control_chars" not in result.signals

    def test_has_bidi_controls_helper(self):
        normalizer = TextNormalizer()
        assert normalizer.has_bidi_controls(f"Hello {RLO}world")
        assert not normalizer.has_bidi_controls("Hello world")

    def test_strip_bidi_controls_false_preserves_chars(self):
        normalizer = TextNormalizer(strip_bidi_controls=False)
        text = f"Hello {RLO}world"
        result = normalizer.normalize(text)
        assert RLO in result.normalized
        assert "bidi_control_chars" not in result.signals

    def test_was_obfuscated_true_for_bidi(self):
        normalizer = TextNormalizer()
        result = normalizer.normalize(f"ignore {RLO}instructions")
        assert result.was_obfuscated is True

    def test_multiple_bidi_chars_all_stripped(self):
        normalizer = TextNormalizer()
        text = f"{LRO}start{RLO}middle{RLM}end{PDI}"
        result = normalizer.normalize(text)
        for ch in [LRO, RLO, RLM, PDI]:
            assert ch not in result.normalized
