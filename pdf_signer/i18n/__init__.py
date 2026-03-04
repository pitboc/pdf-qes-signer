# SPDX-License-Identifier: GPL-3.0-or-later
"""
Internationalisation (i18n) for PDF QES Signer.

Usage:
    from pdf_signer.i18n import t, i18n
    label = t("menu_file")
    i18n.lang = "en"
"""

from __future__ import annotations

from .de import TRANSLATIONS as _DE
from .en import TRANSLATIONS as _EN

TRANSLATIONS: dict[str, dict[str, str]] = {
    "de": _DE,
    "en": _EN,
}

AVAILABLE_LANGUAGES: dict[str, str] = {
    "de": "Deutsch",
    "en": "English",
}


class I18n:
    """Singleton that provides locale-aware string lookup."""

    def __init__(self, lang: str = "de") -> None:
        self._lang = lang if lang in TRANSLATIONS else "de"

    @property
    def lang(self) -> str:
        return self._lang

    @lang.setter
    def lang(self, value: str) -> None:
        if value in TRANSLATIONS:
            self._lang = value

    def t(self, key: str, **kwargs) -> str:
        """Return the translated string for *key*, formatted with *kwargs*."""
        text = TRANSLATIONS[self._lang].get(
            key, TRANSLATIONS["de"].get(key, key)
        )
        if kwargs:
            try:
                return text.format(**kwargs)
            except KeyError:
                return text
        return text


# Module-level singleton – import and mutate `.lang` to switch language.
i18n = I18n("de")


def t(key: str, **kwargs) -> str:
    """Shortcut for ``i18n.t(key, **kwargs)``."""
    return i18n.t(key, **kwargs)
