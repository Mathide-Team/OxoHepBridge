# oxo-hep-bridge — raccourcis de développement
# Usage: make <cible>
#
# Outillage géré par uv (https://docs.astral.sh/uv/), qui remplace la
# combinaison manuelle venv+pip : `make install`/`dev`
# invoquent `uv sync`, qui crée/actualise .venv à partir de
# pyproject.toml + uv.lock (dépendances figées, résolution
# reproductible) et installe le paquet en editable — pas d'activation
# manuelle du venv nécessaire, `uv run <cmd>` (utilisé ci-dessous par
# RUFF/MYPY/PYTEST/PY) résout l'environnement tout seul. Voir
# docs/architecture.md, section « Gestion des dépendances et de
# l'environnement (uv) ».

UV ?= uv
RUFF ?= $(UV) run ruff
MYPY ?= $(UV) run mypy
PYTEST ?= $(UV) run pytest
PY ?= $(UV) run python

.PHONY: install dev lock lint format typecheck test test-cov package clean run-dry run-live i18n-update i18n-check i18n-report

install: dev
	@$(UV) run pre-commit install
	@echo "✓ Environnement prêt (.venv géré par uv) : uv run <cmd>, ou source .venv/bin/activate"

# Synchronise .venv sur uv.lock (extra "dev" inclus) — crée le venv au
# besoin, ne le recrée pas s'il est déjà à jour.
dev:
	@$(UV) sync --extra dev

# Régénère uv.lock après un ajout/changement de dépendance dans
# pyproject.toml (à committer avec le changement).
lock:
	@$(UV) lock

lint:
	@$(RUFF) check .
	@$(RUFF) format --check .

format:
	@$(RUFF) format .

typecheck:
	@$(MYPY)

test:
	@$(PYTEST) -ra

test-cov:
	@$(PYTEST) --cov=oxo_hep_bridge --cov-report=term-missing --cov-fail-under=80

# Archive de livraison horodatée (dist/oxo-hep-bridge-{timestamp}.zip) —
# ne jamais reconstruire ce zip à la main avec `zip -x`, voir
# tools/package.py et docs/pitfalls.md (.github/ perdu à plusieurs
# reprises par un motif d'exclusion approximatif).
package:
	@$(PY) tools/package.py

# Internationalisation gettext (issue #50, docs/i18n.md) : nécessite les
# outils GNU gettext (apt-get install gettext).
i18n-update:
	@$(PY) tools/i18n.py update
	@$(PY) tools/i18n.py compile

i18n-check:
	@$(PY) tools/i18n.py check

i18n-report:
	@$(PY) tools/i18n.py report

# Dry-run sur une capture d'exemple (sans envoyer de HEP)
run-dry:
	@$(PY) -m oxo_hep_bridge.cli \
		--pcap sample_captures/ua3g_freeseating_ipv4.pcap \
		--dry-run

# Capture live (interface + port à adapter)
run-live:
	@$(PY) -m oxo_hep_bridge.cli \
		--interface eth0 \
		--bpf "udp port 32640" \
		--hep-host 127.0.0.1 --hep-port 9060

clean:
	rm -rf .venv .pytest_cache .ruff_cache .mypy_cache .coverage build dist *.egg-info
