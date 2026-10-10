"""Internationalisation (GNU gettext) de oxo-hep-bridge — issue #50.

Les chaînes destinées à l'utilisateur (aide argparse, messages de journal,
messages d'erreur) passent par ``_()`` / ``ngettext()``. La langue source
est le français : sans catalogue pour la langue demandée, ou sans
traduction d'une chaîne, ``_()`` renvoie le texte français d'origine
(``fallback=True``) — le comportement par défaut est donc strictement
identique à celui d'avant l'internationalisation.

Aucune liste de langues n'est codée ici : la langue est choisie par les
variables standard de gettext (``LANGUAGE``, ``LC_ALL``, ``LC_MESSAGES``,
``LANG``), et les catalogues disponibles sont ceux compilés dans
``locale/<langue>/LC_MESSAGES/oxo-hep-bridge.mo`` à côté de ce module
(installés avec le paquet). La liste des langues maintenues vit dans
``lang/LINGUAS`` (outillage : ``tools/i18n.py``, ``docs/i18n.md``).
"""

from __future__ import annotations

import gettext
from pathlib import Path

DOMAIN = "oxo-hep-bridge"
LOCALE_DIR = Path(__file__).resolve().parent / "locale"

# Catalogue courant, dans un conteneur mutable plutôt qu'une variable
# globale réaffectée (``install`` le remplace).
_state: dict[str, gettext.NullTranslations] = {
    "translation": gettext.translation(DOMAIN, localedir=LOCALE_DIR, fallback=True)
}


def install(
    localedir: Path | str | None = None, languages: list[str] | None = None
) -> gettext.NullTranslations:
    """(Re)charge le catalogue — utile aux tests et à un futur ``--lang``.

    Sans argument, relit l'environnement courant ; ``languages`` force
    une liste de langues (ex. ``["de_DE"]``) comme ``LANGUAGE``.
    """
    translation = gettext.translation(
        DOMAIN,
        localedir=Path(localedir) if localedir is not None else LOCALE_DIR,
        languages=languages,
        fallback=True,
    )
    _state["translation"] = translation
    return translation


def _(message: str) -> str:
    """Traduction de ``message`` (texte français d'origine à défaut)."""
    return _state["translation"].gettext(message)


def ngettext(singular: str, plural: str, count: int) -> str:
    """Forme singulier/pluriel traduite selon ``count``."""
    return _state["translation"].ngettext(singular, plural, count)
