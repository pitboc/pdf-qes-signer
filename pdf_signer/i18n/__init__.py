# SPDX-License-Identifier: GPL-3.0-or-later
"""
Internationalisation (i18n) for PDF QES Signer.

Translations are stored as GNU gettext .po/.mo files under
``pdf_signer/locale/<lang>/LC_MESSAGES/pdf_signer.mo``.

Usage::

    from pdf_signer.i18n import t, i18n
    label = t("menu_file")
    i18n.lang = "en"

The module-level singleton ``i18n`` holds the active language.  Assigning
``i18n.lang`` reloads the translation catalogue immediately; no restart is
required.

Fallback chain: target language → German → key name.
"""

from __future__ import annotations

import gettext
from pathlib import Path

_LOCALE_DIR = Path(__file__).parent.parent / "locale"
_DOMAIN = "pdf_signer"

AVAILABLE_LANGUAGES: dict[str, str] = {
    "de": "Deutsch",
    "en": "English",
    "fr": "Français",
    "es": "Español",
    "it": "Italiano",
    "nl": "Nederlands",
    "pl": "Polski",
    "pt": "Português",
}


def _load(lang: str) -> gettext.NullTranslations:
    """Load translation catalogue for *lang*, with German as fallback."""
    de_trans: gettext.NullTranslations
    try:
        de_trans = gettext.translation(
            _DOMAIN, localedir=str(_LOCALE_DIR), languages=["de"]
        )
    except FileNotFoundError:
        de_trans = gettext.NullTranslations()

    if lang == "de":
        return de_trans

    try:
        trans = gettext.translation(
            _DOMAIN, localedir=str(_LOCALE_DIR), languages=[lang]
        )
        trans.add_fallback(de_trans)
        return trans
    except FileNotFoundError:
        return de_trans


class I18n:
    """Singleton that provides locale-aware string lookup."""

    def __init__(self, lang: str = "de") -> None:
        self._lang = lang if lang in AVAILABLE_LANGUAGES else "de"
        self._trans = _load(self._lang)

    @property
    def lang(self) -> str:
        return self._lang

    @lang.setter
    def lang(self, value: str) -> None:
        if value in AVAILABLE_LANGUAGES and value != self._lang:
            self._lang = value
            self._trans = _load(value)

    def t(self, key: str, **kwargs: object) -> str:
        """Return the translated string for *key*, formatted with *kwargs*."""
        text = self._trans.gettext(key)
        if kwargs:
            try:
                return text.format(**kwargs)
            except KeyError:
                return text
        return text


# Module-level singleton – import and mutate `.lang` to switch language.
i18n = I18n("de")


def t(key: str, **kwargs: object) -> str:
    """Shortcut for ``i18n.t(key, **kwargs)``."""
    return i18n.t(key, **kwargs)
