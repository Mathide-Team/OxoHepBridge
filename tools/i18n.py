#!/usr/bin/env python3
"""Outillage gettext de oxo-hep-bridge (issue #50).

Sous-commandes (``uv run python tools/i18n.py <commande>``) :

- ``extract`` : xgettext sur ``src/oxo_hep_bridge`` -> ``lang/messages.pot`` ;
- ``update``  : extract, puis msgmerge de chaque langue de ``lang/LINGUAS``
  (catalogue créé par msginit s'il manque) — les traductions existantes
  sont conservées, les nouvelles chaînes arrivent avec ``msgstr ""`` ;
- ``compile`` : msgfmt de chaque ``lang/<langue>.po`` vers
  ``src/oxo_hep_bridge/locale/<langue>/LC_MESSAGES/oxo-hep-bridge.mo``
  (embarqué dans le paquet, aucune liste de langues dans le code) ;
- ``check``   : échoue si un ``.po`` est invalide (``msgfmt --check``), si
  ``messages.pot`` ne correspond plus aux sources, si un ``.po`` n'est pas
  synchronisé avec le ``.pot``, s'il référence un fichier supprimé, si
  ``LINGUAS`` et ``lang/*.po`` divergent, ou si un ``.mo`` est périmé ;
- ``report``  : résumé (langues, messages, traduits, non traduits, fuzzy),
  en Markdown avec ``--markdown`` (``$GITHUB_STEP_SUMMARY`` en CI).

La liste des langues vit uniquement dans ``lang/LINGUAS`` (une par ligne,
``#`` pour les commentaires) : ajouter une langue = y ajouter son code puis
lancer ``update`` et ``compile``. Les chaînes ne sont jamais traduites
automatiquement : une chaîne nouvelle reste ``msgstr ""`` jusqu'à sa
traduction par une personne.
"""

from __future__ import annotations

import argparse
import re
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
PACKAGE_DIR = REPO_ROOT / "src" / "oxo_hep_bridge"
LANG_DIR = REPO_ROOT / "lang"
POT_PATH = LANG_DIR / "messages.pot"
LINGUAS_PATH = LANG_DIR / "LINGUAS"
LOCALE_DIR = PACKAGE_DIR / "locale"
DOMAIN = "oxo-hep-bridge"

# En-têtes variables d'une génération à l'autre : ignorés par les
# comparaisons de ``check`` (seul le contenu des messages compte).
_VOLATILE_HEADERS = re.compile(r'^"(POT-Creation-Date|PO-Revision-Date|X-Generator): .*\\n"$', re.M)


class I18nError(RuntimeError):
    """Erreur de l'outillage (outil gettext absent, catalogue invalide...)."""


def _run(cmd: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
    if shutil.which(cmd[0]) is None:
        raise I18nError(f"{cmd[0]} introuvable : installez gettext (apt-get install gettext)")
    # Outils gettext du système, arguments construits ici (pas d'entrée externe).
    return subprocess.run(cmd, check=False, capture_output=True, text=True, **kwargs)  # noqa: S603


def _checked(cmd: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
    result = _run(cmd, **kwargs)
    if result.returncode != 0:
        raise I18nError(f"{' '.join(cmd)} : {result.stderr.strip()}")
    return result


def linguas(path: Path | None = None) -> list[str]:
    """Langues déclarées dans ``lang/LINGUAS`` (ordre conservé, sans doublon)."""
    seen: list[str] = []
    for line in (path or LINGUAS_PATH).read_text(encoding="utf-8").splitlines():
        for code in line.split("#", 1)[0].split():
            if code not in seen:
                seen.append(code)
    return seen


def source_files() -> list[Path]:
    """Sources Python scannées, chemins triés relatifs au dépôt."""
    return sorted(
        p.relative_to(REPO_ROOT) for p in PACKAGE_DIR.rglob("*.py") if "locale" not in p.parts
    )


def generate_pot(output: Path) -> Path:
    """xgettext -> ``output`` (emplacements par fichier, sans numéro de
    ligne : une édition du code ne rend pas le .pot obsolète si les chaînes
    ne changent pas)."""
    cmd = [
        "xgettext",
        "--language=Python",
        "--from-code=UTF-8",
        "--keyword=_",
        "--keyword=ngettext:1,2",
        "--add-comments=Translators:",
        "--add-location=file",
        "--sort-by-file",
        "--no-wrap",
        f"--package-name={DOMAIN}",
        "--msgid-bugs-address=https://github.com/Mathide-Team/OxoHepBridge/issues",
        "--output",
        str(output),
        *[str(p) for p in source_files()],
    ]
    _checked(cmd, cwd=REPO_ROOT)
    text = output.read_text(encoding="utf-8").replace("charset=CHARSET", "charset=UTF-8")
    output.write_text(text, encoding="utf-8")
    return output


def _normalized(text: str) -> str:
    """Contenu comparable d'un catalogue : sans en-têtes volatils ni coupures
    de lignes (les versions de gettext ne coupent pas les longues chaînes au
    même endroit, ex. ``Plural-Forms`` de ru_RU)."""
    return re.sub(r'"\n"', "", _VOLATILE_HEADERS.sub("", text))


def _replace_if_changed(new: Path, target: Path) -> bool:
    """Remplace ``target`` par ``new`` seulement si le contenu des messages
    a changé (dates d'en-tête ignorées) : un ``update`` sans changement de
    chaîne ne produit aucun diff dans git."""
    if target.exists() and _normalized(target.read_text(encoding="utf-8")) == _normalized(
        new.read_text(encoding="utf-8")
    ):
        new.unlink()
        return False
    new.replace(target)
    return True


def extract() -> Path:
    LANG_DIR.mkdir(exist_ok=True)
    fresh = generate_pot(POT_PATH.with_suffix(".pot.new"))
    _replace_if_changed(fresh, POT_PATH)
    return POT_PATH


def _new_po(lang: str, po: Path) -> None:
    """Nouveau catalogue vide (en-tête et Plural-Forms par msginit).

    msginit pré-remplit les catalogues anglais avec le msgid : la langue
    source étant le français, ce serait une fausse traduction. msgfilter
    vide donc tous les msgstr (en-tête conservé).
    """
    _checked(
        [
            "msginit",
            "--no-translator",
            "--no-wrap",
            f"--locale={lang}.UTF-8",
            f"--input={POT_PATH}",
            f"--output-file={po}",
        ],
        cwd=REPO_ROOT,
    )
    # Le filtre doit lire son entrée : `true` sortait sans la lire, et
    # msgfilter échouait par intermittence (« write to true subprocess
    # failed: Broken pipe », vu en CI le 2026-10-10 sur la PR #55).
    _checked(
        [
            "msgfilter",
            "--keep-header",
            "--no-wrap",
            f"--input={po}",
            f"--output-file={po}",
            "sh",
            "-c",
            "cat >/dev/null",
        ]
    )


def _merge(po: Path, pot: Path, output: Path) -> None:
    _checked(
        [
            "msgmerge",
            "--quiet",
            "--no-fuzzy-matching",
            "--add-location=file",
            "--sort-by-file",
            "--no-wrap",
            f"--output-file={output}",
            str(po),
            str(pot),
        ]
    )


def update() -> list[str]:
    """extract + msgmerge de chaque langue ; renvoie les langues créées."""
    extract()
    created = []
    for lang in linguas():
        po = LANG_DIR / f"{lang}.po"
        if not po.exists():
            _new_po(lang, po)
            created.append(lang)
        merged = po.with_suffix(".po.new")
        _merge(po, POT_PATH, merged)
        _replace_if_changed(merged, po)
    return created


def mo_path(lang: str, locale_dir: Path | None = None) -> Path:
    return (locale_dir or LOCALE_DIR) / lang / "LC_MESSAGES" / f"{DOMAIN}.mo"


def compile_catalogs(locale_dir: Path | None = None) -> list[Path]:
    written = []
    for lang in linguas():
        target = mo_path(lang, locale_dir)
        target.parent.mkdir(parents=True, exist_ok=True)
        _checked(["msgfmt", "--check", f"--output-file={target}", str(LANG_DIR / f"{lang}.po")])
        written.append(target)
    return written


@dataclass
class CatalogStats:
    lang: str
    translated: int = 0
    untranslated: int = 0
    fuzzy: int = 0
    ok: bool = True

    @property
    def total(self) -> int:
        return self.translated + self.untranslated + self.fuzzy


_STATS = re.compile(r"(\d+) (translated|untranslated|fuzzy)")


def catalog_stats(lang: str) -> CatalogStats:
    po = LANG_DIR / f"{lang}.po"
    result = _run(
        ["msgfmt", "--check", "--statistics", "--output-file=/dev/null", str(po)],
        env={"LC_ALL": "C"},
    )
    stats = CatalogStats(lang, ok=result.returncode == 0)
    for count, kind in _STATS.findall(result.stderr):
        setattr(stats, kind, int(count))
    return stats


def check() -> list[str]:
    """Liste des problèmes (vide = tout est cohérent)."""
    problems: list[str] = []
    declared = linguas()
    present = sorted(p.stem for p in LANG_DIR.glob("*.po"))
    for lang in sorted(set(declared) - set(present)):
        problems.append(
            f"{lang} : déclarée dans lang/LINGUAS mais lang/{lang}.po absent (lancez update)"
        )
    for lang in sorted(set(present) - set(declared)):
        problems.append(f"{lang} : lang/{lang}.po présent mais absent de lang/LINGUAS")
    existing = {str(p) for p in source_files()}
    with tempfile.TemporaryDirectory() as tmp:
        fresh = generate_pot(Path(tmp) / "messages.pot")
        if not POT_PATH.exists() or _normalized(
            POT_PATH.read_text(encoding="utf-8")
        ) != _normalized(fresh.read_text(encoding="utf-8")):
            problems.append("lang/messages.pot ne correspond plus aux sources (lancez update)")
        for lang in sorted(set(declared) & set(present)):
            po = LANG_DIR / f"{lang}.po"
            result = _run(["msgfmt", "--check", "--output-file=/dev/null", str(po)])
            if result.returncode != 0:
                problems.append(f"{lang} : catalogue invalide : {result.stderr.strip()}")
                continue
            merged = Path(tmp) / f"{lang}.po"
            _merge(po, fresh, merged)
            if _normalized(merged.read_text(encoding="utf-8")) != _normalized(
                po.read_text(encoding="utf-8")
            ):
                problems.append(
                    f"{lang} : lang/{lang}.po n'est pas synchronisé avec les sources (lancez update)"
                )
            for ref in re.findall(r"^#: (.+)$", po.read_text(encoding="utf-8"), re.M):
                for path in ref.split():
                    if path not in existing:
                        problems.append(f"{lang} : référence vers un fichier supprimé : {path}")
            target = mo_path(lang)
            fresh_mo = Path(tmp) / f"{lang}.mo"
            _checked(["msgfmt", f"--output-file={fresh_mo}", str(po)])
            if not target.exists() or target.read_bytes() != fresh_mo.read_bytes():
                problems.append(
                    f"{lang} : {target.name} de {lang} périmé ou absent (lancez compile)"
                )
    return problems


def report(markdown: bool = False) -> str:
    rows = [catalog_stats(lang) for lang in linguas()]
    total_messages = max((r.total for r in rows), default=0)
    sums = {k: sum(getattr(r, k) for r in rows) for k in ("translated", "untranslated", "fuzzy")}
    ok = sum(r.ok for r in rows)
    if markdown:
        lines = [
            "## Internationalisation",
            "",
            "| Indicateur | Valeur |",
            "| --- | --- |",
            f"| Langues | {len(rows)} |",
            f"| Messages par catalogue | {total_messages} |",
            f"| Traduits (toutes langues) | {sums['translated']} |",
            f"| Non traduits | {sums['untranslated']} |",
            f"| Fuzzy | {sums['fuzzy']} |",
            f"| Catalogues valides | {ok}/{len(rows)} |",
            "",
            "| Langue | Traduits | Non traduits | Fuzzy |",
            "| --- | ---: | ---: | ---: |",
            *[f"| {r.lang} | {r.translated} | {r.untranslated} | {r.fuzzy} |" for r in rows],
        ]
    else:
        lines = [
            "Internationalisation",
            "─" * 30,
            f"Langues :                {len(rows)}",
            f"Messages par catalogue : {total_messages}",
            f"Traduits :               {sums['translated']}",
            f"Non traduits :           {sums['untranslated']}",
            f"Fuzzy :                  {sums['fuzzy']}",
            "",
            f"Catalogues valides :     {ok}/{len(rows)}",
        ]
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="tools/i18n.py", description=__doc__.split("\n\n")[0])
    sub = parser.add_subparsers(dest="command", required=True)
    for name in ("extract", "update", "compile", "check"):
        sub.add_parser(name)
    rep = sub.add_parser("report")
    rep.add_argument("--markdown", action="store_true")
    args = parser.parse_args(argv)
    try:
        if args.command == "extract":
            print(f"écrit : {extract().name}")
        elif args.command == "update":
            created = update()
            print(
                f"catalogues synchronisés : {len(linguas())}"
                + (f" (créés : {', '.join(created)})" if created else "")
            )
        elif args.command == "compile":
            print(f"catalogues compilés : {len(compile_catalogs())}")
        elif args.command == "check":
            problems = check()
            for problem in problems:
                print(f"ERREUR {problem}", file=sys.stderr)
            if problems:
                return 1
            print(f"catalogues cohérents : {len(linguas())}")
        else:
            sys.stdout.write(report(markdown=args.markdown))
    except I18nError as exc:
        print(f"ERREUR {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
