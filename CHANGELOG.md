# Changelog

Tous les changements notables de oxo-hep-bridge sont documentés ici.
Ce projet suit les conventions de [Semantic Versioning](https://semver.org/lang/fr/).

Cet index reste volontairement court : une entrée par session, avec un
résumé de quelques lignes et un lien vers le détail complet (raisonnement,
décisions de conception, chiffres de vérification) dans
[`docs/sessions/`](docs/sessions/). Voir aussi
[`docs/roadmap.md`](docs/roadmap.md) pour l'état courant du projet.

## Issue #47 — 2026-10-10

Démo HOMER7 : `deploy/homer/compose.yml` (heplify-server, PostgreSQL,
homer-app), `config/oxo-hep-bridge.homer-demo.toml` et
`deploy/homer/README.md`. Premier test contre un vrai collecteur : les
3 captures d'exemple arrivent en base en UDP, TCP et TLS. Nouvelle option
`--pcap-retime` (TOML `pcap_retime`, `OXOHEP_PCAP_RETIME`) : sans elle,
heplify-server rejette les captures anciennes (pas de partition pour leur
date). Confirmé : payload compressé et keepalive reçus mais non stockés
(heplify-server exige payload et Correlation ID). 15 tests
(`tests/test_pcap_retime.py`, `tests/test_homer_demo.py`).

## Issue #50 — 2026-10-10

Internationalisation gettext sur le modèle de Gcm4 : module
`oxo_hep_bridge.i18n` (`_()`/`ngettext()`, repli sur le français), toutes
les chaînes utilisateur enveloppées (f-strings converties en `.format()`
nommé), 29 catalogues `lang/*.po` (msgstr vides, aucune traduction
automatique) listés dans `lang/LINGUAS`, `.mo` embarqués dans le paquet,
outillage `tools/i18n.py` (`extract`/`update`/`compile`/`check`/`report`)
et cibles `make i18n-*`, workflow `.github/workflows/i18n.yml`
(vérification, rapport, PR optionnelle), 21 tests (`tests/test_i18n.py`).
Détail : [docs/i18n.md](docs/i18n.md).

## Session 45 — 2026-09-15

Backlog `docs/roadmap.md` § « À faire » toujours vide depuis la
session 42 : conformément à `docs/session-protocol.md`, audit empirique
du dernier document exploratoire signalé « pas encore audité »,
`docs/ua3g-call-signaling-decroche-numerotation.md` (mentionné depuis la
session 43, vérifié manuellement une fois en session 30 mais jamais
protégé par un test). Vérifié ligne à ligne contre un vrai `tshark`
(réseau disponible ce sandbox, comme aux sessions 24/37/44) sur les 3
captures d'exemple : table des opcodes `uaudp.opcode` 0-7 et leurs
libellés natifs, unique occurrence de `hook_status` (frame 119, message
`IP Device Routing: Init`), absence totale de `digit_dialed.digit_value`/
`key_number`, durées/comptages des 3 captures — **tout confirmé exact,
aucune correction nécessaire**. Lacune trouvée et comblée (même nature
qu'en session 43 pour l'autre document) : ce constat n'était protégé par
aucun test. 11 nouveaux tests de garde-fou ajoutés dans
`tests/test_real_tshark_integration.py` (skip automatique si `tshark`
indisponible). **414 tests passés + 1 skip IPv6** (415 au total),
**couverture 99,46 %** (stable), `mypy`/`ruff check`/`ruff format --check`
verts.

→ [Détail complet](docs/sessions/session-45.md)

## Session 44 — 2026-09-15

Demande explicite : migration de l'outillage de développement vers
[uv](https://docs.astral.sh/uv/) (« remplacer poetry » — le projet n'a en
réalité jamais utilisé Poetry, vérifié par recherche exhaustive ; traité
comme un remplacement de la combinaison manuelle `python3 -m venv` + `pip
install -e ".[dev]"`, jusque-là utilisée dans `Makefile`/`install.sh`).
`uv.lock` ajouté et committé (dépendances figées, reproductibles) ;
`Makefile`/`install.sh`/`.github/workflows/ci.yml` migrés vers `uv sync`/
`uv run` (CI durcie avec `uv sync --locked`, échoue si le lock diverge du
`pyproject.toml` plutôt que de le régénérer silencieusement) ; structure
de `pyproject.toml` inchangée (`[project.optional-dependencies].dev`
reste la source des dépendances de dev). `ruff check`/`ruff format
--check`/`mypy` déjà entièrement verts avant toute modification (rien à
corriger), restés verts après. 6 nouveaux tests de garde-fou dans
`tests/test_ci_config.py` (CI/Makefile/install.sh utilisent bien `uv`,
aucune commande de bootstrap pip/venv résiduelle) ; `uv.lock`/
`pyproject.toml` ajoutés aux fichiers de suivi protégés par
`tests/test_packaging.py`. Réseau et `tshark` réel disponibles ce
sandbox (comme en session 37) : suite complète reconfirmée contre un vrai
`tshark`, aucune régression trouvée sur le pipeline. **404 tests** (403
passés + 1 skip IPv6), **couverture 99,46 %**, `mypy`/`ruff check`/`ruff
format --check` verts.

→ [Détail complet](docs/sessions/session-44.md)

## Session 43 — 2026-09-15

Backlog `docs/roadmap.md` § « À faire » vide depuis la session 42 :
conformément à `docs/session-protocol.md`, audit empirique de plusieurs
affirmations documentaires plutôt que de rester sans rien produire.
Vérifiées et confirmées exactes (aucune correction nécessaire) :
pourcentage de perte de contenu NOE sur les opcodes UAUDP 16-23
(163/993, ~16 %), tailles des tables `ua_opcode_names.py` (40/4
entrées), table complète des chunks HEP de `docs/hep-chunks.md`
contre `hep.py` (y compris le cas keepalive sans Correlation ID), et
décodage du payload compressé par `tools/hep_receiver.py`. Une lacune
trouvée : le détail par opcode et la rythmique temporelle de
`docs/noe-ua3g-homer-mapping.md#6ter` (table « Le motif ») — vérifiés
exacts (comptage et timestamps réels tirés de la fixture `uaudp_ipv6`)
mais jusqu'ici protégés par aucun test, contrairement au total agrégé
(protégé depuis la session 20). 3 nouveaux tests de garde-fou ajoutés
dans `tests/test_fields.py` pour combler cette lacune. Mention
désormais obsolète d'un décompte figé (« 751 occurrences `assert` »,
session 40) corrigée dans `docs/roadmap.md` pour ne plus se démoder à
chaque session (785 aujourd'hui, croissance normale). **398 tests,
couverture 99,46 %**, `mypy`/`ruff check`/`ruff format --check` verts.

→ [Détail complet](docs/sessions/session-43.md)

## Session 42 — 2026-09-15

Dernier candidat du backlog de `docs/roadmap.md` implémenté : exploiter
`Stats.to_dict()` (testé pour lui-même depuis plusieurs sessions, jamais
consommé) pour une sortie d'observabilité structurée. Choix tranché entre
les deux pistes identifiées en session 39 : sink JSON loguru
(`logger.add(sink, serialize=True)`), pas de fichier « textfile
collector » Prometheus séparé. Nouvelle option `logging.json_file`
(`--log-json-file` / `OXOHEP_LOG_JSON_FILE` / `[logging] json_file`) :
quand renseignée, `cli.py` ajoute un sink JSON Lines en plus de stderr, et
`Stats.log_summary()` (`stats.py`) ainsi que le log de progression
(`bridge.py`) lient désormais le dict complet de `to_dict()` à leur
enregistrement via `logger.bind(stats=...)` — visible sous
`record.extra.stats` dans ce sink, invisible côté texte humain (vérifié
empiriquement, comportement historique inchangé par défaut). `README.md`/
`docs/architecture.md`/`config/oxo-hep-bridge.example.toml` mis à jour ;
`docs/roadmap.md` § « À faire » désormais vide (les trois candidats de
l'audit de session 39 sont tous implémentés). **395 tests, couverture
99,46 %**, `mypy`/`ruff check`/`ruff format --check` verts.

→ [Détail complet](docs/sessions/session-42.md)

## Session 41 — 2026-09-14

Poursuite du backlog de `docs/roadmap.md` : dernier candidat restant
implémenté, sans enchaîner sur le suivant (`Stats.to_dict()`) ni sur le
candidat 0x14 déjà écarté. `TCPSender._connect()` (`sender.py`) active
désormais `TCP_NODELAY` sur la socket brute juste après `connect()`, avant
l'éventuel enrobage TLS — l'algorithme de Nagle, actif par défaut,
retardait sinon l'émission de chaque paquet HEP déjà envoyé
individuellement via `sendall()`. Changement d'une ligne dans `_connect()`,
comportement vérifié par mock (`setsockopt` appelé avec les bons
arguments, avant tout enrobage TLS — 2 tests) et sur une vraie socket TCP
loopback (`getsockopt` relit `1` après connexion — test existant inversé).
`docs/roadmap.md`/`docs/architecture.md` mis à jour en conséquence
(candidat retiré du backlog, limite connue retirée ; un seul candidat
reste ouvert). **383 tests, couverture 99,46 %**, `mypy`/`ruff
check`/`ruff format --check` verts.

→ [Détail complet](docs/sessions/session-41.md)

## Session 40 — 2026-09-14

Deux volets demandés explicitement dans le même message : correction de
tous les signalements ruff repérés en session 39, puis implémentation
d'un candidat du backlog. Ruff `TRY`/`S` activés (`pyproject.toml`) et 11
signalements réels traités (3 `assert` remplacés par des gardes
explicites testées, survivant à `python -O` ; 1 `TRY300` restructuré ; 7
`S104` annotés, dont 6 faux positifs sur des valeurs `"0.0.0.0"`
neutres). Candidat roadmap #1 implémenté : `UDPSender` connecte
désormais sa socket au premier envoi, ce qui permet de détecter un
collecteur UDP injoignable (`ConnectionRefusedError`) là où l'ancien
`sendto()` non connecté l'ignorait silencieusement — changement d'une
ligne, `sendto()` inchangé pour l'envoi lui-même (vérifié empiriquement
qu'il reste compatible avec une socket connectée). `docs/roadmap.md`/
`docs/architecture.md` mis à jour en conséquence (candidat retiré du
backlog, limite connue retirée). **381 tests, couverture 99,46 %**,
`mypy`/`ruff check`/`ruff format --check` verts.

→ [Détail complet](docs/sessions/session-40.md)

## Session 39 — 2026-09-13

Session d'audit demandée explicitement (avec Context7 pour ancrer les
propositions dans une documentation à jour), sans implémentation
(« sans passer à la suite ») : suite complète rejouée réellement (état de
la session 38 confirmé exact), candidat 0x14 reconfirmé absent des
captures. Deux constats réseau nouveaux sur `sender.py`, vérifiés
empiriquement et figés par deux nouveaux tests permanents sur sockets
loopback réelles : `UDPSender` (envoi non connecté) ne détecte jamais un
collecteur UDP injoignable ; `TCPSender` n'active jamais `TCP_NODELAY`
(Nagle actif malgré des paquets envoyés individuellement). `Stats.to_dict()`
identifié comme testé mais jamais consommé. Trois candidats ajoutés à
`docs/roadmap.md` § « À faire » (classés par impact, tous indépendants),
plus une note secondaire sur l'élargissement `ruff` (`TRY`/`S`, 24
signalements mineurs trouvés à l'essai). **378 tests, couverture 99,45 %**
(+2 tests, aucun changement dans `src/oxo_hep_bridge`).

→ [Détail complet](docs/sessions/session-39.md)

## Session 38 — 2026-09-12

Backlog toujours vide → poursuite de l'audit de complétude du nommage IP Device Routing avec `tshark` réel disponible : toutes les valeurs `ua3g.ip`/`ua3g.ip.cs`/champs de paramètre réellement présentes dans `sample_captures/*.pcap` recoupées contre les tables de `ua_opcode_names.py`. Un seul écart trouvé — identifiant 0x0C, déjà résolu en `None` et absent aussi de la table officielle Wireshark amont, pas une lacune du projet — comportement déjà correct. Audit transformé en garde-fou permanent : `tests/test_ua3g_ip_device_routing_completeness.py` (6 tests, `tshark` réel). **376 tests, couverture 99,45 %.**

→ [Détail complet](docs/sessions/session-38.md)

## Session 37 — 2026-09-11

Backlog toujours vide → nouvelle vérification empirique (réseau disponible dans ce sandbox) : `tshark` réel réinstallé et pipeline rejoué de bout en bout (`tests/test_real_tshark_integration.py`, 3/3 verts, chiffres identiques à la session 24). Recherche élargie du candidat 0x14 « Application Parameters » (rejeté en session 35 faute de fixture) directement sur les trois captures **complètes** de `sample_captures/` plutôt que sur leurs fixtures trimées : aucune occurrence, rejet renforcé. Aucun défaut trouvé, documentation mise à jour en conséquence. **370 tests, couverture 99,45 %.**

→ [Détail complet](docs/sessions/session-37.md)

## Session 36 — 2026-09-11

Backlog vide → vérification empirique (protocole `docs/session-protocol.md`) : `.github/workflows/ci.yml`, déjà signalé disparu à deux reprises dans `docs/pitfalls.md` (sessions 17, 27), a de nouveau disparu de la dernière archive livrée (session 35) — cause confirmée : motif d'exclusion `zip -x '*.git*'` matchant `.github` par sous-chaîne. Correction définitive : `tools/package.py`/`make package` remplacent tout zip manuel, exclusion par égalité exacte de segment de chemin ; `tests/test_packaging.py` construit une vraie archive à chaque run pour vérifier son contenu. **370 tests, couverture 99,45 %.**

→ [Détail complet](docs/sessions/session-36.md)

## Session 35 — 2026-09-10

Mapping des identifiants de paramètre de la sous-commande 0x11 « Free Seating » de IP Device Routing : nouvelle table dédiée `UA3G_IP_DEVICE_ROUTING_FREESEATING_PARAMETER_NAMES` (4 entrées, `ip_device_routing_cmd_freeseating_vals[]`) ; doublement consécutif des valeurs vérifié sur les fixtures réelles, comme pour la sous-commande 0x0A en session 34. Backlog `docs/roadmap.md` de nouveau vide. **366 tests, couverture 99,45 %.**

→ [Détail complet](docs/sessions/session-35.md)

## Session 34 — 2026-09-10

Mapping des identifiants de paramètre poste de la sous-commande 0x0A « Set Parameters Value » de IP Device Routing : nouvelle table dédiée `UA3G_IP_DEVICE_ROUTING_SET_PARAMETER_NAMES` (40 entrées, distincte de celle des sous-commandes 0x09/0x02) ; même doublement consécutif des valeurs que la session 33, mais découvert ici côté requête système plutôt que réponse terminal. **361 tests, couverture 99,45 %.**

→ [Détail complet](docs/sessions/session-34.md)

## Session 33 — 2026-09-09

Mapping des identifiants de paramètre poste (sous-commandes 0x09/0x02 de IP Device Routing) : nouvelle fonction `decode_names()` pour les champs listes ; doublement de valeurs côté réponse identifié et vérifié dans le dissecteur upstream. **356 tests, couverture 99,45 %.**

→ [Détail complet](docs/sessions/session-33.md)

## Session 32 — 2026-09-09

Mapping des sous-commandes IP Device Routing (opcode UA3G 0x13) : `ip_name`/`ip_cs_name`, auto-disambiguïsés par le dissecteur ALE selon le sens du message.

→ [Détail complet](docs/sessions/session-32.md)

## Session 31 — 2026-09-08

Nommage protocolaire officiel pour les opcodes UA3G (65 + 33 entrées, System→Terminal et Terminal→Système, tables distinctes selon le sens déduit des ports par défaut).

→ [Détail complet](docs/sessions/session-31.md)

## Session 30 — 2026-09-08

Correctif d'extraction : `build_semantic_payload()` cherchait les champs UA3G à plat (`ua3g_ua3g_*`) alors que tshark les imbrique toujours sous une clé `ua3g` — 11 paquets désormais correctement extraits.

→ [Détail complet](docs/sessions/session-30.md)

## Session 29 — 2026-09-07

Correction documentaire : `docs/ua3g-call-signaling-decroche-numerotation.md` était orphelin, non lié depuis README/architecture.md/CLAUDE.md.

→ [Détail complet](docs/sessions/session-29.md)

## Session 28 — 2026-09-06

Audit documentaire étendu (chunks, graphe d'imports, `install.sh`, unité systemd) : `HepPacket._FIELD_CHUNKS` se présentait comme « source de vérité » sans être référencé nulle part — corrigé par un nouveau test.

→ [Détail complet](docs/sessions/session-28.md)

## Session 27 — 2026-09-06

Correction CI : `.github/workflows/ci.yml` avait de nouveau disparu du dépôt (probable perte lors d'un export/zip qui ne préserve pas les dossiers cachés).

→ [Détail complet](docs/sessions/session-27.md)

## Session 26 — 2026-09-06

Correction documentaire : les 22 variables d'environnement `OXOHEP_*` n'apparaissaient jamais dans le tableau d'options du README.

→ [Détail complet](docs/sessions/session-26.md)

## Session 25 — 2026-09-06

Correction documentaire : la clé TOML `tshark_path`, réelle et fonctionnelle, était absente de `config/oxo-hep-bridge.example.toml`.

→ [Détail complet](docs/sessions/session-25.md)

## Session 24 — 2026-09-06

Première intégration bout-en-bout avec un vrai `tshark` (`apt-get install tshark`, jamais tenté avant) : chiffres exacts conformes à la doc sur les 3 captures d'exemple.

→ [Détail complet](docs/sessions/session-24.md)

## Session 23 — 2026-09-05

Premier sandbox avec accès réseau depuis la session 20 : confirmation empirique complète (317 tests, couverture 99,42 %, mypy/ruff verts) — clôt la réserve « à reconfirmer » des sessions 21/22.

→ [Détail complet](docs/sessions/session-23.md)

## Session 22 — 2026-09-05

Garde-fou anti-cycle d'imports (`tests/test_no_cross_imports.py`), suite à une comparaison externe du projet contre un catalogue de motifs non métier.

→ [Détail complet](docs/sessions/session-22.md)

## Session 21 — 2026-09-05

Correction documentaire : `--tshark-path` et `--correlation-field` existaient dans le CLI sans figurer dans le tableau du README. Aucun accès réseau dans ce sandbox.

→ [Détail complet](docs/sessions/session-21.md)

## Session 20 — 2026-09-05

Correction documentaire : le pourcentage de perte de contenu NOE (opcode UAUDP ≥ 16) était resté à ~12 % sans être recalculé — un comptage réel donne 163/993 (~16,4 %).

→ [Détail complet](docs/sessions/session-20.md)

## Session 19 — 2026-09-05

Correction documentaire : `docs/hep-chunks.md` annonçait le chunk Correlation ID comme « toujours présent » sans distinguer le paquet keepalive, qui ne le porte jamais. **Création de `CLAUDE.md`.**

→ [Détail complet](docs/sessions/session-19.md)

## Session 18 — 2026-08-29

Correction documentaire : le docstring de `fields.extract_noe_events` affirmait à tort qu'aucune capture ne contient de champ `noe` — infirmé par une exécution réelle (28/64 paquets concernés).

→ [Détail complet](docs/sessions/session-18.md)

## Session 17 — 2026-08-29

Première exécution réelle de la suite avec accès réseau depuis l'ajout du contrôle de type : révèle `.github/workflows/ci.yml` absent du dépôt, une violation ruff et un écart `make lint`/README — tous corrigés. 310 tests.

→ [Détail complet](docs/sessions/session-17.md)

## Session 16 — 2026-08-29

Documentation : remontée de la perte de contenu NOE sur les trames « canal local » (opcode UAUDP ≥ 16) dans `architecture.md` § Limites connues (outillage indisponible dans ce sandbox, aucun code touché).

→ [Détail complet](docs/sessions/session-16.md)

## Session 15 — 2026-08-29

Durcissement tests + mypy : couverture 90 % → 99,4 % (238 → 306 tests) ; 1 bug réel corrigé (`OXOHEP_DECODE_AS`) et 3 erreurs mypy latentes résolues au passage.

→ [Détail complet](docs/sessions/session-15.md)

## Session 14 — 2026-08-28

Vérification bout-en-bout : la payload JSON produite correspond bien à `docs/noe-ua3g-homer-mapping.md`, sur les 3 captures d'exemple (sans instance HOMER réelle).

→ [Détail complet](docs/sessions/session-14.md)

## Session 13 — 2026-08-28

Nommage protocolaire officiel UAUDP/NOE (`ua_opcode_names.py`), sourcé depuis le dissecteur Wireshark officiel ALE et recoupé avec les captures d'exemple.

→ [Détail complet](docs/sessions/session-13.md)

## Session 12 — 2026-08-28

Durcissement CI : `mypy` + seuil de couverture minimal (80 %) ajoutés à `ci.yml` — a révélé et corrigé un pattern `hasattr`/`getattr` invisible pour mypy dans `Bridge.run()`.

→ [Détail complet](docs/sessions/session-12.md)

## Session 11 — 2026-08-28

Notification systemd (`sd_notify`) : `READY=1`/`STOPPING=1`/`WATCHDOG=1`, sans dépendance à `libsystemd`.

→ [Détail complet](docs/sessions/session-11.md)

## Session 10 — 2026-08-28

Validation explicite du TOML (`ConfigError`) : table/clé inconnue fait échouer le démarrage avec un message ciblé, plutôt que d'être ignorée silencieusement.

→ [Détail complet](docs/sessions/session-10.md)

## Session 9 — 2026-08-28

Fréquence du log de progression configurable (`--stats-interval`), `0` pour désactiver sans affecter le résumé de fin de run.

→ [Détail complet](docs/sessions/session-09.md)

## Session 8 — 2026-08-28

Retry avec backoff exponentiel sur échec d'envoi HEP (`--hep-retries`/`--hep-retry-backoff`), sur les trois transports.

→ [Détail complet](docs/sessions/session-08.md)

## Session 7 — 2026-08-27

Compression gzip optionnelle du payload (chunk 0x0010) — **vérifiée non décodée par HOMER11 en l'état** (lecture du code source réel), désactivée par défaut avec avertissement explicite.

→ [Détail complet](docs/sessions/session-07.md)

## Session 6 — 2026-08-26

Transport HEP configurable : TCP et TCP+TLS en plus d'UDP, vérification de certificat activée par défaut, CA personnalisée, bascule labo `--hep-tls-insecure`.

→ [Détail complet](docs/sessions/session-06.md)

## Session 5 — 2026-08-26

Création de `docs/roadmap.md` (état fait / à faire / reporté), liée depuis le README.

→ [Détail complet](docs/sessions/session-05.md)

## Session 4 — 2026-08-26

Résolution IPv4/IPv6/DNS de `--hep-host` via `getaddrinfo()` — corrige un échec silencieux en IPv6 littéral.

→ [Détail complet](docs/sessions/session-04.md)

## Session 3 — 2026-08-26

Arrêt propre sur `SIGTERM` en plus de `SIGINT` (requis pour `systemctl stop`). 78 tests.

→ [Détail complet](docs/sessions/session-03.md)

## Session 2 — 2026-08-26

Documentation exploratoire NOE/UA3G ↔ SIP/HOMER (`docs/noe-ua3g-homer-mapping.md`) : explique pourquoi aucun mapping opcode → événement métier n'est codé en dur. 73 tests.

→ [Détail complet](docs/sessions/session-02.md)

## Session 1 — 2026-08-25 → 2026-08-26

Version `0.1.0` initiale : encodeur/décodeur HEPv3 pur Python, source `tshark -T ek`, normaliseur UAUDP/UA3G/NOE, mode live/pcap, 33 tests. Puis dans la foulée : payload sémantique structuré, corrélation stateless canonicalisée, `stats.py`, harnais `tools/hep_receiver.py` (60 tests) ; puis keepalive HEP périodique (69 tests).

→ [Détail complet](docs/sessions/session-01.md)

