# Pièges déjà rencontrés — oxo-hep-bridge

Importé par [`CLAUDE.md`](../CLAUDE.md) (`@docs/pitfalls.md`) : chargé
automatiquement à chaque démarrage de session — c'est le sens de cette liste
(ne pas répéter), pas besoin de l'ouvrir à la main.

- Ne jamais ignorer silencieusement une clé TOML inconnue — `Config` valide
  explicitement chaque table (`ConfigError`), toute nouvelle clé doit être
  ajoutée à la fois au dataclass concerné et au frozenset `_XXX_KEYS`
  correspondant dans `config.py`, **et** à
  `config/oxo-hep-bridge.example.toml` (même commentée) — sinon elle reste
  fonctionnelle mais non documentée, comme `tshark_path` jusqu'à la session
  25 (garde-fou désormais dans
  `test_all_config_keys_documented_in_example_toml`).
- Ne pas contourner un problème de typage mypy par un `hasattr()`/
  `getattr()` ou un `# type: ignore` local : corriger à la racine (cf.
  `Sender.retry_count`/`Sender.close()` déclarés sur la classe de base,
  session 15).
- Un fichier de référence (mapping, doc exploratoire) ajouté au dépôt doit
  être lié depuis le README/architecture.md, pas laissé orphelin — voir les
  garde-fous dans `tests/test_docs.py`.
- Avant d'affirmer qu'un chunk/champ est « toujours présent » ou qu'une
  fixture « ne contient jamais X », vérifier en rejouant le pipeline réel
  plutôt que de faire confiance à un commentaire existant — deux
  corrections de ce type ont déjà été nécessaires (sessions 18 et 19).
- Quand le réseau/l'outillage (`pytest`/`mypy`/`ruff`, installation de
  `loguru`) est indisponible dans le sandbox (sessions 12, 16, 21, 22 —
  pas systématique, voir sessions 17/18/19/20/23 où il l'était), ça n'empêche pas
  de rejouer le pipeline réel sur les fixtures existantes : un stub minimal
  pour `loguru` (la seule dépendance externe du projet, `logger.add/remove/
  debug/info/warning/error/exception`) posé hors du dépôt suffit à importer
  `src/oxo_hep_bridge/*`, puis `subprocess.Popen` peut être patché à la main
  comme le fait `FakePopen` de `tests/conftest.py`. Un nouveau test ajouté
  dans ces conditions doit être validé manuellement (script Python
  reproduisant son assertion) et le fait signalé explicitement dans
  CHANGELOG/roadmap — ne jamais deviner ni recopier un décompte de tests
  qui n'a pas été réellement exécuté (voir note existante sur les sessions
  16/17 pour le même principe côté décompte manuel).
- `.github/workflows/ci.yml` a disparu du dépôt à trois reprises déjà
  (sessions 17, 27 puis 35) alors que `tests/test_ci_config.py` le
  documente et le vérifie censément depuis la session 17 — sans qu'aucune
  modification volontaire du fichier ne soit en cause dans le CHANGELOG
  entre les trois. Cause confirmée en session 35 : le fichier étant dans
  un dossier caché (`.github/`), un export/zip manuel avec un motif
  d'exclusion approximatif du type `zip -x '*.git*'` (censé écarter un
  éventuel `.git/`) l'exclut aussi, `.github` contenant la sous-chaîne
  `.git`. **Corrigé en session 35** : `tools/package.py`/`make package`
  remplacent tout zip manuel — l'exclusion s'y fait par égalité exacte de
  segment de chemin (`EXCLUDED_DIR_NAMES`), jamais par un motif "contient
  git" — et `tests/test_packaging.py` construit une vraie archive à
  chaque run de la suite pour vérifier que `.github/workflows/ci.yml` (et
  plus généralement les fichiers de suivi/doc) y est bien présent. En
  session, continuer malgré tout à lancer `pytest` avant de conclure
  qu'il n'y a « rien à faire » : ce garde-fou protège la livraison future,
  pas les zips déjà produits par le passé.
- Quand le réseau est disponible, `apt-get install tshark` fonctionne dans
  ce type de sandbox (Ubuntu) — jamais tenté avant la session 24, qui a
  découvert que cela permet de rejouer tout le pipeline contre un vrai
  subprocess `tshark -T ek` plutôt que contre les fixtures `.ek.ndjson`
  figées rejouées par `FakePopen`. Voir `tests/test_real_tshark_integration.py`
  (skip automatique si `tshark` reste indisponible, comme `requires_ipv6`
  dans `test_sender.py`) : à lancer en plus de `pytest`/`mypy`/`ruff` chaque
  fois que ce sandbox a du réseau, ça ne coûte que quelques secondes et
  referme un angle mort resté longtemps non vérifié (aucune session
  précédente n'avait de trace d'un vrai `tshark` disponible). Réseau et
  `tshark` de nouveau disponibles en session 44 (comme en session 37) ;
  ni l'un ni l'autre ne le sont systématiquement d'une session à l'autre.
  Session 44 : sandbox tournant en `root` (`sudo` absent du PATH,
  `EUID=0`) — `apt-get install` fonctionne alors directement sans `sudo`,
  ne pas conclure à un réseau/outillage indisponible sur un simple échec
  de `sudo -n true`, vérifier `$EUID`/`whoami` d'abord.
- Une affirmation documentaire non vérifiée ne vit pas seulement dans les
  fichiers `.md` : `HepPacket._FIELD_CHUNKS` (`hep.py`) se déclarait comme
  « reproductible pour les tests » sans être référencée par aucun test ni
  par `encode()` lui-même (session 28). Quand une constante du code se
  présente en commentaire comme une « source de vérité » ou un contrat
  (« ordre canonique », « tenu à jour manuellement », etc. — comme
  `_CAPTURE_KEYS`/`_HEP_KEYS` dans `config.py`, réellement exploitées par
  `test_docs.py`), vérifier par un `grep` du nom sur tout le dépôt qu'elle
  est bien utilisée quelque part, plutôt que de supposer qu'un docstring
  qui semble sérieux est nécessairement vérifié.

- Rejouer un pcap ancien vers HOMER7 sans `--pcap-retime` : heplify-server
  reçoit tout (compteurs Prometheus à jour) mais n'insère rien, avec
  seulement `pq: no partition of relation "hep_proto_100_default" found
  for row` dans ses journaux. Les tables sont partitionnées autour de la
  date du jour. Vérifié en issue #47 (`deploy/homer/README.md`).
- Un paquet reçu par heplify-server n'est pas forcément en base : pour le
  type LOG (100), payload **et** Correlation ID doivent être non vides.
  D'où l'absence en base du payload compressé (`--hep-compress-payload`) et
  du keepalive, sans aucune erreur côté collecteur (issue #47).
