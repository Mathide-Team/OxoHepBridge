#!/usr/bin/env python3
"""Internationalisation gettext (issue #50).

Trois familles de garde-fous :

1. exécution : sans traduction, ``_()`` rend le texte français d'origine
   (comportement inchangé) ; avec un catalogue, la traduction est servie ;
   chaque langue de ``lang/LINGUAS`` a son ``.mo`` embarqué et chargeable ;
2. sources : toute chaîne destinée à l'utilisateur (aide argparse,
   messages de journal info/warning/error, messages d'exception) passe par
   ``_()`` ; aucune liste de langues n'est codée dans le paquet ;
3. outillage ``tools/i18n.py`` : catalogues cohérents avec les sources
   (``check``), détection des catalogues invalides, des chaînes nouvelles,
   des ``.mo`` périmés, conservation des traductions par ``update``.

Les tests qui appellent les outils GNU gettext se sautent proprement si
``msgfmt``/``xgettext`` sont absents (comme les tests tshark réels).
"""

from __future__ import annotations

import ast
import gettext
import shutil
import subprocess
import tomllib
from pathlib import Path

import pytest
import tools.i18n as tool

from oxo_hep_bridge import i18n

REPO_ROOT = Path(__file__).parent.parent
PACKAGE_DIR = REPO_ROOT / "src" / "oxo_hep_bridge"

needs_gettext = pytest.mark.skipif(
    not all(shutil.which(t) for t in ("xgettext", "msgmerge", "msgfmt", "msginit", "msgfilter")),
    reason="outils GNU gettext absents (apt-get install gettext)",
)

STOP_MSG = "Arrêt demandé (SIGINT/SIGTERM), fermeture du subprocess tshark..."


@pytest.fixture
def _restore_catalog():
    yield
    i18n.install()


# --------------------------------------------------------------------- #
# 1. Exécution
# --------------------------------------------------------------------- #


def test_sans_traduction_texte_francais_d_origine(_restore_catalog):
    i18n.install(languages=["xx_XX"])
    assert i18n._(STOP_MSG) == STOP_MSG
    assert i18n.ngettext("{} paquet", "{} paquets", 2) == "{} paquets"
    assert i18n.ngettext("{} paquet", "{} paquets", 1) == "{} paquet"


@needs_gettext
def test_catalogue_traduit_servi(tmp_path, _restore_catalog):
    po = tmp_path / "de.po"
    po.write_text(
        'msgid ""\nmsgstr ""\n"Content-Type: text/plain; charset=UTF-8\\n"\n'
        '"Plural-Forms: nplurals=2; plural=(n != 1);\\n"\n\n'
        f'msgid "{STOP_MSG}"\nmsgstr "Stopp angefordert"\n\n'
        'msgid "{} paquet"\nmsgid_plural "{} paquets"\nmsgstr[0] "{} Paket"\nmsgstr[1] "{} Pakete"\n',
        encoding="utf-8",
    )
    mo = tmp_path / "de_DE" / "LC_MESSAGES" / f"{i18n.DOMAIN}.mo"
    mo.parent.mkdir(parents=True)
    subprocess.run(["msgfmt", "--check", "-o", str(mo), str(po)], check=True)  # noqa: S603, S607

    i18n.install(localedir=tmp_path, languages=["de_DE"])
    assert i18n._(STOP_MSG) == "Stopp angefordert"
    assert i18n.ngettext("{} paquet", "{} paquets", 3) == "{} Pakete"
    assert i18n._("chaîne absente du catalogue") == "chaîne absente du catalogue"


def test_chaque_langue_declaree_a_son_catalogue_embarque():
    langs = tool.linguas()
    assert len(langs) == 29
    for lang in langs:
        assert tool.mo_path(lang).is_file(), lang
        gettext.translation(
            i18n.DOMAIN, localedir=i18n.LOCALE_DIR, languages=[lang]
        )  # lève si absent


def test_catalogues_embarques_dans_le_paquet():
    with (REPO_ROOT / "pyproject.toml").open("rb") as f:
        data = tomllib.load(f)["tool"]["setuptools"]["package-data"]["oxo_hep_bridge"]
    assert "locale/*/LC_MESSAGES/*.mo" in data


# --------------------------------------------------------------------- #
# 2. Sources
# --------------------------------------------------------------------- #

_LOG_LEVELS = {"info", "warning", "error", "critical", "success", "exception"}
_EXCEPTIONS = {"ConfigError", "ValueError", "RuntimeError", "TsharkError", "TypeError"}
_KEYWORDS = {"help", "description", "epilog"}


def _is_gettext_call(node: ast.AST) -> bool:
    """``_("...")`` ou ``_("...").format(...)``."""
    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "format"
        and isinstance(node.func.value, ast.Call)
    ):
        node = node.func.value
    return (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id in {"_", "ngettext"}
    )


def _user_strings_not_translated() -> list[str]:
    fautes = []
    for path in sorted(PACKAGE_DIR.glob("*.py")):
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if not isinstance(node, ast.Call):
                continue
            candidates = []
            func = node.func
            if (
                isinstance(func, ast.Attribute)
                and func.attr in _LOG_LEVELS
                and isinstance(func.value, ast.Name)
                and func.value.id == "logger"
                and node.args
            ):
                candidates.append(node.args[0])
            if isinstance(func, ast.Name) and func.id in _EXCEPTIONS and node.args:
                candidates.append(node.args[0])
            candidates += [k.value for k in node.keywords if k.arg in _KEYWORDS]
            for value in candidates:
                literal = isinstance(value, ast.JoinedStr) or (
                    isinstance(value, ast.Constant) and isinstance(value.value, str)
                )
                if literal and not _is_gettext_call(value):
                    fautes.append(f"{path.name}:{value.lineno}")
    return fautes


def test_chaines_utilisateur_passent_par_gettext():
    assert _user_strings_not_translated() == []


def test_le_garde_fou_detecte_une_chaine_oubliee(tmp_path, monkeypatch):
    (tmp_path / "x.py").write_text(
        'logger.warning("oubli")\nraise ValueError(f"oubli {x}")\np.add_argument("--a", help=_("ok"))\n',
        encoding="utf-8",
    )
    monkeypatch.setattr(f"{__name__}.PACKAGE_DIR", tmp_path)
    assert _user_strings_not_translated() == ["x.py:1", "x.py:2"]


def test_aucune_langue_codee_en_dur_dans_le_paquet():
    langs = set(tool.linguas())
    for path in PACKAGE_DIR.glob("*.py"):
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                assert node.value not in langs, f"{path.name}:{node.lineno} : {node.value!r}"


def test_linguas_sans_doublon_et_fichiers_alignes(tmp_path):
    (tmp_path / "LINGUAS").write_text(
        "# commentaire\nde_DE fr_FR\nde_DE  # doublon\n\nja_JP\n", encoding="utf-8"
    )
    assert tool.linguas(tmp_path / "LINGUAS") == ["de_DE", "fr_FR", "ja_JP"]
    assert sorted(p.stem for p in tool.LANG_DIR.glob("*.po")) == sorted(tool.linguas())


# --------------------------------------------------------------------- #
# 3. Outillage
# --------------------------------------------------------------------- #


@needs_gettext
def test_catalogues_du_depot_coherents():
    assert tool.check() == []


@pytest.fixture
def lang_copy(tmp_path, monkeypatch):
    """Copie de lang/ et des .mo dans tmp_path ; l'outil y travaille."""
    lang = tmp_path / "lang"
    shutil.copytree(tool.LANG_DIR, lang)
    locale = tmp_path / "locale"
    shutil.copytree(tool.LOCALE_DIR, locale)
    monkeypatch.setattr(tool, "LANG_DIR", lang)
    monkeypatch.setattr(tool, "POT_PATH", lang / "messages.pot")
    monkeypatch.setattr(tool, "LINGUAS_PATH", lang / "LINGUAS")
    monkeypatch.setattr(tool, "LOCALE_DIR", locale)
    return lang


def _translate(po: Path, msgid: str, msgstr: str) -> None:
    text = po.read_text(encoding="utf-8")
    old = f'msgid "{msgid}"\nmsgstr ""\n'
    assert old in text
    po.write_text(text.replace(old, f'msgid "{msgid}"\nmsgstr "{msgstr}"\n'), encoding="utf-8")


@needs_gettext
def test_catalogue_invalide_detecte(lang_copy):
    po = lang_copy / "de_DE.po"
    po.write_text(po.read_text(encoding="utf-8") + '\nmsgid "sans fin\n', encoding="utf-8")
    assert any("de_DE : catalogue invalide" in p for p in tool.check())


@needs_gettext
def test_format_incoherent_detecte(lang_copy):
    po = lang_copy / "de_DE.po"
    text = po.read_text(encoding="utf-8").replace(
        'msgid "tshark stderr : {}"\nmsgstr ""',
        '#, python-format\nmsgid "%d x"\nmsgstr "%s y"\n\nmsgid "z"\nmsgstr ""',
    )
    po.write_text(text, encoding="utf-8")
    assert any("de_DE : catalogue invalide" in p for p in tool.check())


@needs_gettext
def test_chaine_nouvelle_ou_supprimee_detectee(lang_copy):
    pot = lang_copy / "messages.pot"
    pot.write_text(
        pot.read_text(encoding="utf-8").replace(STOP_MSG, "ancienne chaîne"), encoding="utf-8"
    )
    problems = tool.check()
    assert "lang/messages.pot ne correspond plus aux sources (lancez update)" in problems


@needs_gettext
def test_po_desynchronise_et_reference_supprimee(lang_copy):
    po = lang_copy / "it_IT.po"
    po.write_text(
        po.read_text(encoding="utf-8")
        + '\n#: src/oxo_hep_bridge/supprime.py\nmsgid "fantôme"\nmsgstr ""\n',
        encoding="utf-8",
    )
    problems = tool.check()
    assert any("it_IT : lang/it_IT.po n'est pas synchronisé" in p for p in problems)
    assert any(
        "référence vers un fichier supprimé : src/oxo_hep_bridge/supprime.py" in p for p in problems
    )


@needs_gettext
def test_linguas_et_fichiers_divergents(lang_copy):
    with (lang_copy / "LINGUAS").open("a", encoding="utf-8") as fh:
        fh.write("eo\n")
    (lang_copy / "sv_SE.po").rename(lang_copy / "sv.po")
    problems = tool.check()
    assert any(p.startswith("eo : déclarée dans lang/LINGUAS") for p in problems)
    assert any(
        p.startswith("sv : lang/sv.po présent mais absent de lang/LINGUAS") for p in problems
    )


@needs_gettext
def test_update_conserve_les_traductions_et_cree_les_langues(lang_copy):
    _translate(lang_copy / "de_DE.po", STOP_MSG, "Stopp angefordert")
    with (lang_copy / "LINGUAS").open("a", encoding="utf-8") as fh:
        fh.write("eo\n")
    created = tool.update()
    assert created == ["eo"]
    assert 'msgstr "Stopp angefordert"' in (lang_copy / "de_DE.po").read_text(encoding="utf-8")
    eo = (lang_copy / "eo.po").read_text(encoding="utf-8")
    assert f'msgid "{STOP_MSG}"\nmsgstr ""' in eo


@needs_gettext
def test_update_ne_traduit_pas_automatiquement_l_anglais(lang_copy):
    (lang_copy / "en_US.po").unlink()
    tool.update()
    assert tool.catalog_stats("en_US").translated == 0


@needs_gettext
def test_update_sans_changement_ne_touche_a_rien(lang_copy):
    avant = {p.name: p.read_bytes() for p in lang_copy.iterdir()}
    tool.update()
    assert {p.name: p.read_bytes() for p in lang_copy.iterdir()} == avant


@needs_gettext
def test_mo_perime_detecte_puis_recompile(lang_copy):
    _translate(lang_copy / "fr_FR.po", STOP_MSG, "Arrêt demandé")
    assert any("fr_FR : " in p and "périmé" in p for p in tool.check())
    assert len(tool.compile_catalogs()) == 29
    assert tool.check() == []


@needs_gettext
def test_rapport(lang_copy):
    _translate(lang_copy / "de_DE.po", STOP_MSG, "Stopp angefordert")
    stats = tool.catalog_stats("de_DE")
    assert stats.translated == 1 and stats.untranslated == stats.total - 1 and stats.ok
    texte = tool.report()
    assert "Langues :                29" in texte
    assert "Traduits :               1" in texte
    assert "Catalogues valides :     29/29" in texte
    markdown = tool.report(markdown=True)
    assert "| Langues | 29 |" in markdown and "| de_DE | 1 |" in markdown


@needs_gettext
def test_cli(lang_copy, capsys):
    assert tool.main(["check"]) == 0
    assert tool.main(["report", "--markdown"]) == 0
    assert "## Internationalisation" in capsys.readouterr().out
    (lang_copy / "de_DE.po").write_text("msgid \n", encoding="utf-8")
    assert tool.main(["check"]) == 1


def test_outil_absent(monkeypatch):
    monkeypatch.setattr(tool.shutil, "which", lambda _name: None)
    with pytest.raises(tool.I18nError, match="installez gettext"):
        tool.catalog_stats("de_DE")
    assert tool.main(["extract"]) == 2


def test_comparaison_insensible_aux_coupures_de_lignes():
    """Les versions de gettext coupent les longues chaînes à des endroits
    différents (Plural-Forms de ru_RU sur le runner de CI) : ce n'est pas une
    désynchronisation."""
    coupe = 'msgstr ""\n"Plural-Forms: nplurals=3; plural=(n%10==1 && "\n"n%100!=11 ? 0 : 2);\\n"\n'
    entier = 'msgstr ""\n"Plural-Forms: nplurals=3; plural=(n%10==1 && n%100!=11 ? 0 : 2);\\n"\n'
    assert tool._normalized(coupe) == tool._normalized(entier)
    assert tool._normalized('"POT-Creation-Date: 2026-01-01\\n"\n') == tool._normalized(
        '"POT-Creation-Date: 2027-02-02\\n"\n'
    )
