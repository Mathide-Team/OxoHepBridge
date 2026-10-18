# CLAUDE.md — guide de session pour oxo-hep-bridge

Fichier volontairement court : ce qu'une session doit lire à son
démarrage. Le détail (protocole complet, pièges accumulés, backlog) est
importé ci-dessous plutôt que dupliqué ici — Claude Code charge ces
fichiers automatiquement via `@chemin`, inutile de les rouvrir à la main
sauf besoin ponctuel.

## État courant

415 tests (414 passés + 1 skip conditionnel — IPv6 indisponible dans le
sandbox de la session 45, mais `tshark` réel l'était), couverture 99,46 %,
`mypy`/`ruff check`/`ruff format --check` verts. Dernière session : 45
(2026-09-15). Chiffres et détail : @docs/roadmap.md

## Prochaine feature

Toujours aucun candidat de nouvelle fonctionnalité vérifié dans
`docs/roadmap.md` § « À faire » (backlog vide depuis la session 42). La
session 45 a suivi la procédure prescrite par `docs/session-protocol.md` :
audit empirique du dernier document exploratoire signalé non audité
(`docs/ua3g-call-signaling-decroche-numerotation.md`) — entièrement
confirmé exact contre un vrai `tshark`, 11 nouveaux tests de garde-fou
ajoutés pour protéger ce constat (jusque-là seulement vérifié une fois en
session 30, jamais figé par un test). Les deux documents exploratoires du
projet ont désormais chacun leur constat empirique central protégé par
des tests automatisés.

Une future session à backlog vide devra trouver une nouvelle piste
d'audit (relecture plus fine de `docs/architecture.md`, `docs/hep-
chunks.md`, `README.md`, ou tout autre fichier de suivi pas encore
recoupé ligne à ligne avec le code/les captures — voir
`docs/session-protocol.md`) ou traiter une demande explicite hors backlog
comme en session 44 (migration uv).

## Commandes

Environnement géré par [uv](https://docs.astral.sh/uv/) (migration session
44, remplace pip+venv manuels — voir
docs/architecture.md#gestion-des-dépendances-et-de-lenvironnement-uv) :

```bash
make install    # uv sync --extra dev (venv + deps dev) + pre-commit
make test       # uv run pytest
make test-cov   # uv run pytest + couverture (échoue sous 80 %, comme la CI)
make lint       # uv run ruff check + ruff format --check
make typecheck  # uv run mypy (src/oxo_hep_bridge + tools/, PAS tests/ —
                # volontaire, voir docs/architecture.md#contrôle-de-type-statique-mypy)
```

Aucun `tshark` n'est nécessaire pour `make test` (fixtures `.ndjson`
rejouées par `FakePopen`) ; requis seulement en usage réel ou pour
`tests/test_real_tshark_integration.py` (skip automatique sinon).

## Fichiers de référence

- `docs/architecture.md` — choix techniques, section « Limites connues ».
- `docs/hep-chunks.md` — format HEPv3 exact émis par le pont.
- `docs/noe-ua3g-homer-mapping.md` — mapping exploratoire NOE/UA3G ↔ SIP.
- `docs/ua3g-call-signaling-decroche-numerotation.md` — vrais champs UA3G
  du décroché/numérotation.
- `CHANGELOG.md` — index court, une entrée par session, avec lien vers le
  détail complet.
- `docs/sessions/session-NN.md` — historique détaillé session par session
  (raisonnement, décisions de conception, chiffres de vérification). À
  n'ouvrir que pour un besoin de contexte précis sur une décision passée
  — pas par défaut à chaque démarrage.

## Contexte importé automatiquement

@docs/roadmap.md
@docs/session-protocol.md
@docs/pitfalls.md

## Instructions reçues dans le chat (issue #57)

Toute instruction reçue dans le chat (Perplexity Computer, Claude Code ou autre) devient une issue. Une phrase ne reste pas en l'air.

- Avant de commencer le travail, créer l'issue dans le dépôt concerné, en citant l'instruction mot pour mot avec sa date.
- Une demande qui touche plusieurs dépôts donne une issue par dépôt, chacune liée aux autres.
- Une question posée dans le chat sans réponse immédiate devient elle aussi une issue, ou un commentaire « Question pour Mathilde » sur l'issue existante.
- La PR ferme ou cite l'issue (`Closes #n`). Une instruction abandonnée est fermée avec sa raison (« not planned »).
- En fin de session, vérifier que chaque instruction du chat a son issue, ouverte ou fermée.
