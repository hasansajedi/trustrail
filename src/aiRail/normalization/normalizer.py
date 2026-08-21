"""Text normalization for aiRail.

Normalizes text to expose obfuscation tricks before pattern matching.
"""

from __future__ import annotations

import base64
import binascii
import html
import math
import re
import unicodedata
from dataclasses import dataclass, field
from urllib.parse import unquote

# ── Pre-compiled regexes ──────────────────────────────────────────────────────

# Zero-width and invisible characters
_ZW_CHARS = re.compile(
    r"[\u200b\u200c\u200d\u200e\u200f\u2028\u2029\u2060\u2061\u2062\u2063"
    r"\u2064\ufeff\u00ad\u034f\u115f\u1160\u17b4\u17b5\u3164\uffa0]"
)

# Bidirectional Unicode control characters (U+202A–U+202E, U+2066–U+2069,
# U+200F RIGHT-TO-LEFT MARK, U+061C ARABIC LETTER MARK).
# These characters can reverse displayed text to visually hide injections.
_BIDI_CONTROLS = re.compile(r"[\u200f\u061c\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069]")

# Unicode tag characters can encode invisible ASCII-like payloads. This block
# includes TAG SPACE through CANCEL TAG (U+E0000-U+E007F).
_TAG_CHARS = re.compile(r"[\U000e0000-\U000e007f]")

# Variation selectors alter glyph presentation and can also encode arbitrary
# invisible bytes. Cover both the BMP and supplementary selector ranges.
_VARIATION_SELECTORS = re.compile(r"[\ufe00-\ufe0f\U000e0100-\U000e01ef]")

# Unusual whitespace (not standard ASCII space/newline/tab)
_UNUSUAL_WS = re.compile(r"[\u00a0\u1680\u2000-\u200a\u202f\u205f\u3000]")

# URL-percent-encoded sequences
_PCT_ENCODED = re.compile(r"%[0-9A-Fa-f]{2}")

# Hex-encoded content (0xDEAD or \x41 style)
_HEX_ESCAPE = re.compile(r"(?:0x|\\x)([0-9A-Fa-f]{2,})")

# Base64-like strings (4+ chars, padding optional, urlsafe or standard)
_B64_CANDIDATE = re.compile(r"(?<![A-Za-z0-9+/=])([A-Za-z0-9+/]{20,}={0,2})(?![A-Za-z0-9+/=])")
_B64_URL_CANDIDATE = re.compile(r"(?<![A-Za-z0-9_-])([A-Za-z0-9_-]{20,})(?![A-Za-z0-9_-])")

# Unicode homoglyph mapping (common Cyrillic/Latin look-alikes)
_HOMOGLYPHS: dict[str, str] = {
    "\u0430": "a",  # Cyrillic а
    "\u0435": "e",  # Cyrillic е
    "\u043e": "o",  # Cyrillic о
    "\u0440": "p",  # Cyrillic р
    "\u0441": "c",  # Cyrillic с
    "\u0445": "x",  # Cyrillic х
    "\u0456": "i",  # Cyrillic і
    "\u0410": "A",  # Cyrillic А
    "\u0412": "B",  # Cyrillic В
    "\u0415": "E",  # Cyrillic Е
    "\u041c": "M",  # Cyrillic М
    "\u041d": "H",  # Cyrillic Н
    "\u041e": "O",  # Cyrillic О
    "\u0420": "P",  # Cyrillic Р
    "\u0421": "C",  # Cyrillic С
    "\u0422": "T",  # Cyrillic Т
    "\u0425": "X",  # Cyrillic Х
    "\u0443": "y",  # Cyrillic Т
    "\uff41": "a",  # fullwidth a
    "\uff42": "b",  # fullwidth b
    "\uff43": "c",  # fullwidth c
    "\uff44": "d",  # fullwidth d
    "\uff45": "e",  # fullwidth e
    "\uff46": "f",  # fullwidth f
    "\uff47": "g",  # fullwidth g
    "\uff48": "h",  # fullwidth h
    "\uff49": "i",  # fullwidth i
    "\uff4a": "j",  # fullwidth j
    "\uff4b": "k",  # fullwidth k
    "\uff4c": "l",  # fullwidth l
    "\uff4d": "m",  # fullwidth m
    "\uff4e": "n",  # fullwidth n
    "\uff4f": "o",  # fullwidth o
    "\uff50": "p",  # fullwidth p
    "\uff51": "q",  # fullwidth q
    "\uff52": "r",  # fullwidth r
    "\uff53": "s",  # fullwidth s
    "\uff54": "t",  # fullwidth t
    "\uff55": "u",  # fullwidth u
    "\uff56": "v",  # fullwidth v
    "\uff57": "w",  # fullwidth w
    "\uff58": "x",  # fullwidth x
    "\uff59": "y",  # fullwidth y
    "\uff5a": "z",  # fullwidth z
}


def strip_invisible_unicode(
    text: str,
    *,
    strip_bidi_controls: bool = True,
    strip_zero_width: bool = True,
    strip_tag_chars: bool = True,
    strip_variation_selectors: bool = True,
) -> tuple[str, dict[str, int]]:
    """Strip configured invisible Unicode channels and return removal counts."""
    current = text
    counts: dict[str, int] = {}
    patterns = (
        ("bidi_control_chars", strip_bidi_controls, _BIDI_CONTROLS),
        ("zero_width_chars", strip_zero_width, _ZW_CHARS),
        ("unicode_tag_chars", strip_tag_chars, _TAG_CHARS),
        ("variation_selectors", strip_variation_selectors, _VARIATION_SELECTORS),
    )
    for signal, enabled, pattern in patterns:
        if not enabled:
            continue
        matches = pattern.findall(current)
        if matches:
            counts[signal] = len(matches)
            current = pattern.sub("", current)
    return current, counts


@dataclass
class NormalizationResult:
    """Result of text normalization."""

    original: str
    normalized: str
    signals: list[str] = field(default_factory=list)

    @property
    def was_obfuscated(self) -> bool:
        return len(self.signals) > 0

    @property
    def decoded_variants(self) -> list[str]:
        """Return decoded content variants for pattern matching."""
        variants = [self.normalized]
        if self.original != self.normalized:
            variants.append(self.original)
        return variants


class TextNormalizer:
    """Normalizes text to expose obfuscation tricks."""

    def __init__(
        self,
        decode_html: bool = True,
        decode_url: bool = True,
        decode_unicode: bool = True,
        remove_zero_width: bool = True,
        normalize_whitespace: bool = True,
        map_homoglyphs: bool = True,
        try_decode_base64: bool = True,
        try_decode_hex: bool = True,
        strip_bidi_controls: bool = True,
        strip_tag_chars: bool = True,
        strip_variation_selectors: bool = True,
    ) -> None:
        self.decode_html = decode_html
        self.decode_url = decode_url
        self.decode_unicode = decode_unicode
        self.remove_zero_width = remove_zero_width
        self.normalize_whitespace = normalize_whitespace
        self.map_homoglyphs = map_homoglyphs
        self.try_decode_base64 = try_decode_base64
        self.try_decode_hex = try_decode_hex
        self.strip_bidi_controls = strip_bidi_controls
        self.strip_tag_chars = strip_tag_chars
        self.strip_variation_selectors = strip_variation_selectors

    def normalize(self, text: str) -> NormalizationResult:
        """Normalize text and return result with signals."""
        signals: list[str] = []
        current = text

        # 1. HTML entity decoding
        if self.decode_html:
            decoded = html.unescape(current)
            if decoded != current:
                signals.append("html_entities")
            current = decoded

        # 2. Unicode normalization (NFC)
        if self.decode_unicode:
            nfc = unicodedata.normalize("NFC", current)
            if nfc != current:
                signals.append("unicode_normalization")
            current = nfc

        # 3. URL-percent decoding
        if self.decode_url and _PCT_ENCODED.search(current):
            import contextlib

            with contextlib.suppress(Exception):
                decoded = unquote(current, errors="replace")
                if decoded != current:
                    signals.append("url_encoding")
                current = decoded

        # 4. Invisible Unicode channel removal
        current, invisible_counts = strip_invisible_unicode(
            current,
            strip_bidi_controls=self.strip_bidi_controls,
            strip_zero_width=self.remove_zero_width,
            strip_tag_chars=self.strip_tag_chars,
            strip_variation_selectors=self.strip_variation_selectors,
        )
        signals.extend(invisible_counts)

        # 6. Unusual whitespace normalization
        if self.normalize_whitespace and _UNUSUAL_WS.search(current):
            signals.append("unusual_whitespace")
            current = _UNUSUAL_WS.sub(" ", current)

        # 7. Homoglyph mapping
        if self.map_homoglyphs:
            mapped = "".join(_HOMOGLYPHS.get(ch, ch) for ch in current)
            if mapped != current:
                signals.append("homoglyphs")
            current = mapped

        # 8. Hex escape decoding (\x41 or 0x41 style)
        if self.try_decode_hex:

            def _decode_hex_match(m: re.Match[str]) -> str:
                try:
                    raw = bytes.fromhex(m.group(1))
                    return raw.decode("utf-8", errors="replace")
                except Exception:
                    return m.group(0)

            decoded = _HEX_ESCAPE.sub(_decode_hex_match, current)
            if decoded != current:
                signals.append("hex_encoding")
            current = decoded

        return NormalizationResult(
            original=text,
            normalized=current,
            signals=signals,
        )

    def has_bidi_controls(self, text: str) -> bool:
        """Check for bidirectional Unicode control characters."""
        return bool(_BIDI_CONTROLS.search(text))

    def has_zero_width_chars(self, text: str) -> bool:
        """Check for zero-width characters."""
        return bool(_ZW_CHARS.search(text))

    def has_tag_chars(self, text: str) -> bool:
        """Check for Unicode tag characters."""
        return bool(_TAG_CHARS.search(text))

    def has_variation_selectors(self, text: str) -> bool:
        """Check for BMP or supplementary Unicode variation selectors."""
        return bool(_VARIATION_SELECTORS.search(text))

    def has_unusual_whitespace(self, text: str) -> bool:
        """Check for unusual whitespace characters."""
        return bool(_UNUSUAL_WS.search(text))

    def has_homoglyphs(self, text: str) -> bool:
        """Check for homoglyph characters."""
        return any(ch in _HOMOGLYPHS for ch in text)

    def is_likely_base64(self, text: str) -> bool:
        """Check if text looks like base64-encoded content."""
        m = _B64_CANDIDATE.search(text)
        if not m:
            return False
        candidate = m.group(1)
        return _try_decode_base64(candidate) is not None

    def extract_base64_payloads(self, text: str) -> list[str]:
        """Extract and decode base64-encoded segments."""
        results = []
        for m in _B64_CANDIDATE.finditer(text):
            candidate = m.group(1)
            decoded = _try_decode_base64(candidate)
            if decoded is not None:
                results.append(decoded)
        return results

    def shannon_entropy(self, text: str) -> float:
        """Calculate Shannon entropy of a string."""
        return _shannon_entropy(text)


def _try_decode_base64(s: str) -> str | None:
    """Try to decode a string as base64. Returns None if not valid."""
    # Ensure proper padding
    padded = s + "=" * (4 - len(s) % 4) if len(s) % 4 else s
    for decoder in (base64.b64decode, base64.urlsafe_b64decode):
        try:
            raw = decoder(padded)
            # Must be printable-ish UTF-8
            decoded = raw.decode("utf-8")
            printable = sum(1 for c in decoded if c.isprintable() or c in "\n\r\t")
            if printable / max(len(decoded), 1) > 0.7:
                return decoded
        except (binascii.Error, UnicodeDecodeError, ValueError):
            continue
    return None


def _shannon_entropy(text: str) -> float:
    """Calculate Shannon entropy of a string."""
    if not text:
        return 0.0
    freq: dict[str, int] = {}
    for ch in text:
        freq[ch] = freq.get(ch, 0) + 1
    length = len(text)
    entropy = 0.0
    for count in freq.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy


# Module-level default normalizer instance
_default_normalizer = TextNormalizer()


def normalize(text: str) -> NormalizationResult:
    """Normalize text using default settings."""
    return _default_normalizer.normalize(text)
