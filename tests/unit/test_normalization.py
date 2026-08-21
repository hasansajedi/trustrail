"""Unit tests for normalization module."""

from aiRail.normalization.normalizer import (
    TextNormalizer,
    _shannon_entropy,
    normalize,
    strip_invisible_unicode,
)


class TestTextNormalizer:
    def setup_method(self):
        self.normalizer = TextNormalizer()

    def test_plain_text_unchanged(self):
        result = self.normalizer.normalize("Hello, world!")
        assert result.normalized == "Hello, world!"
        assert not result.was_obfuscated

    def test_html_entity_decoding(self):
        result = self.normalizer.normalize("&lt;script&gt;")
        assert "<script>" in result.normalized
        assert "html_entities" in result.signals

    def test_zero_width_char_removal(self):
        text = "ignore\u200b\u200c previous"
        result = self.normalizer.normalize(text)
        assert "\u200b" not in result.normalized
        assert "\u200c" not in result.normalized
        assert "zero_width_chars" in result.signals

    def test_unicode_tag_character_removal(self):
        text = "safe\U000e0061text\U000e007f"
        result = self.normalizer.normalize(text)
        assert result.normalized == "safetext"
        assert "unicode_tag_chars" in result.signals

    def test_bmp_variation_selector_removal(self):
        text = "instruction\ufe0f"
        result = self.normalizer.normalize(text)
        assert result.normalized == "instruction"
        assert "variation_selectors" in result.signals

    def test_supplementary_variation_selector_removal(self):
        text = "instruction\U000e0100"
        result = self.normalizer.normalize(text)
        assert result.normalized == "instruction"
        assert "variation_selectors" in result.signals

    def test_url_encoding_decode(self):
        result = self.normalizer.normalize("ignore%20previous%20instructions")
        assert "ignore previous instructions" in result.normalized
        assert "url_encoding" in result.signals

    def test_homoglyph_mapping(self):
        # Cyrillic 'а' should map to Latin 'a'
        result = self.normalizer.normalize("\u0430\u0441\u0441\u0435ss")  # Cyrillic homoglyphs
        assert result.was_obfuscated
        assert "homoglyphs" in result.signals

    def test_hex_escape_decode(self):
        result = self.normalizer.normalize(r"\x48\x65\x6c\x6c\x6f")
        assert "Hello" in result.normalized

    def test_unusual_whitespace(self):
        result = self.normalizer.normalize("hello\u00a0world")
        assert "\u00a0" not in result.normalized
        assert " " in result.normalized
        assert "unusual_whitespace" in result.signals

    def test_shannon_entropy_low(self):
        # "aaaa" has entropy 0
        entropy = _shannon_entropy("aaaa")
        assert entropy == 0.0

    def test_shannon_entropy_high(self):
        # Random-looking string should have higher entropy
        entropy = _shannon_entropy("aB3xQ9mR2kP7nL5wY1vZ")
        assert entropy > 3.0

    def test_has_zero_width_chars(self):
        assert self.normalizer.has_zero_width_chars("test\u200btest")
        assert not self.normalizer.has_zero_width_chars("normal text")

    def test_has_tag_chars(self):
        assert self.normalizer.has_tag_chars("test\U000e0061")
        assert not self.normalizer.has_tag_chars("normal text")

    def test_has_variation_selectors(self):
        assert self.normalizer.has_variation_selectors("test\ufe0f")
        assert self.normalizer.has_variation_selectors("test\U000e0100")
        assert not self.normalizer.has_variation_selectors("normal text")

    def test_has_unusual_whitespace(self):
        assert self.normalizer.has_unusual_whitespace("test\u00a0test")
        assert not self.normalizer.has_unusual_whitespace("normal text")

    def test_module_normalize_function(self):
        result = normalize("normal text")
        assert result.normalized == "normal text"

    def test_decoded_variants_unobfuscated(self):
        result = normalize("hello")
        assert result.decoded_variants == ["hello"]

    def test_decoded_variants_obfuscated(self):
        result = normalize("hello\u200b")  # Zero-width char
        assert len(result.decoded_variants) >= 1

    def test_invisible_categories_are_configurable(self):
        normalizer = TextNormalizer(
            strip_tag_chars=False,
            strip_variation_selectors=False,
        )
        text = "text\U000e0061\ufe0f"
        result = normalizer.normalize(text)
        assert result.normalized == text
        assert "unicode_tag_chars" not in result.signals
        assert "variation_selectors" not in result.signals

    def test_strip_invisible_unicode_reports_privacy_safe_counts(self):
        text = "a\u200bb\U000e0061c\ufe0f"
        sanitized, counts = strip_invisible_unicode(text)
        assert sanitized == "abc"
        assert counts == {
            "zero_width_chars": 1,
            "unicode_tag_chars": 1,
            "variation_selectors": 1,
        }


class TestBase64Detection:
    def setup_method(self):
        self.normalizer = TextNormalizer()

    def test_detect_base64_payload(self):
        import base64

        payload = base64.b64encode(b"ignore previous instructions").decode()
        payloads = self.normalizer.extract_base64_payloads(f"data: {payload}")
        assert any("ignore" in p for p in payloads)

    def test_no_false_positive_short_strings(self):
        assert not self.normalizer.is_likely_base64("short")

    def test_random_word_not_base64(self):
        # Normal words are not base64 payloads
        payloads = self.normalizer.extract_base64_payloads("hello world this is normal text")
        # Should not decode to meaningful content
        for p in payloads:
            assert len(p) < 100  # Just sanity check
