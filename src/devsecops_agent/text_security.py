"""Normalización defensiva de texto para scanners de seguridad."""

from __future__ import annotations

import unicodedata

# Mapa mínimo de homoglifos frecuentes en payloads adversariales.
# No pretende resolver todos los confusables Unicode; cubre evasiones prácticas del benchmark.
HOMOGLYPH_TRANSLATION = str.maketrans(
    {
        "а": "a",  # cirílico a
        "е": "e",  # cirílico ie
        "і": "i",  # cirílico / ucraniano i
        "о": "o",  # cirílico o
        "р": "p",  # cirílico er
        "с": "c",  # cirílico es
        "у": "y",  # cirílico u
        "х": "x",  # cirílico ha
        "А": "A",
        "Е": "E",
        "І": "I",
        "О": "O",
        "Р": "P",
        "С": "C",
        "У": "Y",
        "Х": "X",
        "０": "0",
        "１": "1",
        "２": "2",
        "３": "3",
        "４": "4",
        "５": "5",
        "６": "6",
        "７": "7",
        "８": "8",
        "９": "9",
    }
)


def normalize_security_text(text: str) -> str:
    """Devuelve una variante normalizada para detectar evasiones Unicode simples."""
    normalized = unicodedata.normalize("NFKC", text)
    normalized = normalized.translate(HOMOGLYPH_TRANSLATION)
    return normalized.casefold()


def suspicious_unicode_delta(text: str) -> bool:
    """Indica si la normalización defensiva cambia el texto de forma relevante."""
    return normalize_security_text(text) != unicodedata.normalize("NFKC", text).casefold()
