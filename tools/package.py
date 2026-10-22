#!/usr/bin/env python3
"""Construit l'archive de livraison horodatée du dépôt.

Utilisé par `make package` (voir Makefile) et exercé directement par
`tests/test_packaging.py`, qui construit une vraie archive et vérifie son
contenu plutôt que de se fier à la documentation ou de relire le code
d'exclusion à l'œil.

Pourquoi ce script existe : `.github/workflows/ci.yml` a disparu à
plusieurs reprises d'archives de livraison passées (sessions 17, 27 puis
35 — voir docs/pitfalls.md) à cause d'un motif d'exclusion « zip -x
'*.git*' » tapé à la main, censé écarter un éventuel `.git/` mais qui
matche aussi `.github/` (sous-chaîne ``.git`` présente dans les deux). Ce
module remplace tout zip manuel : l'exclusion se fait par comparaison
*exacte* d'un segment de chemin contre une liste explicite
(``EXCLUDED_DIR_NAMES``), jamais par un motif "contient .git" qui
matcherait aussi un dossier cousin.
"""

from __future__ import annotations

import sys
import zipfile
from datetime import datetime
from pathlib import Path

from loguru import logger

REPO_ROOT = Path(__file__).resolve().parent.parent

# Comparaison exacte sur un segment de chemin (jamais une sous-chaîne :
# c'est précisément ce qui a cassé .github/ par le passé, voir
# docs/pitfalls.md). ".git" reste listé par précaution si ce dépôt devient
# un jour un checkout git réel, mais ne doit surtout pas s'écrire ".git*"
# ou "*git*".
EXCLUDED_DIR_NAMES = frozenset(
    {
        ".git",
        ".venv",
        "__pycache__",
        ".pytest_cache",
        ".ruff_cache",
        ".mypy_cache",
        "htmlcov",
        "dist",
    }
)
EXCLUDED_FILE_SUFFIXES = (".pyc",)
EXCLUDED_FILE_NAMES = frozenset({".coverage"})


def build_archive(output_path: Path, source_root: Path = REPO_ROOT) -> Path:
    """Écrit une archive zip de ``source_root`` vers ``output_path`` et la
    renvoie. Exclut uniquement les répertoires/fichiers de
    ``EXCLUDED_DIR_NAMES``/``EXCLUDED_FILE_SUFFIXES``/``EXCLUDED_FILE_NAMES``
    ci-dessus — jamais de motif glob approximatif."""
    logger.debug("build_archive() appelée | sortie={}", output_path.name)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(output_path, "w", zipfile.ZIP_DEFLATED) as archive:
        for path in sorted(source_root.rglob("*")):
            if path.is_dir():
                continue
            rel_parts = path.relative_to(source_root).parts
            if any(part in EXCLUDED_DIR_NAMES for part in rel_parts[:-1]):
                continue
            if path.name in EXCLUDED_FILE_NAMES or path.suffix in EXCLUDED_FILE_SUFFIXES:
                continue
            # Ne jamais inclure l'archive en train de s'écrire elle-même
            # si output_path se trouve sous source_root (cas de dist/).
            if path.resolve() == output_path.resolve():
                continue
            archive.write(path, arcname=str(path.relative_to(source_root)))
    logger.debug("build_archive() retourne | archive écrite")
    return output_path


def main() -> int:
    logger.debug("main() appelée")
    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    output = REPO_ROOT / "dist" / f"oxo-hep-bridge-{timestamp}.zip"
    build_archive(output)
    print(output)
    logger.debug("main() retourne | 0 (archive construite)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
