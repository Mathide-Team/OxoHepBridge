# Roadmap

État courant et suite envisagée pour `oxo-hep-bridge`. Ce document ne
liste que ce qui est *vrai aujourd'hui* : le raisonnement, les décisions
de conception et le détail par session sont dans
[`CHANGELOG.md`](../CHANGELOG.md) (index court) et
[`docs/sessions/`](sessions/) (détail complet, un fichier par session) —
ce document n'y renvoie que pour ne pas dupliquer.

## État actuel

**415 tests** (414 passés + 1 skip conditionnel — IPv6 indisponible dans
le sandbox de la session 45 ; `tshark` réel, lui, l'était — installable
sans sudo, ce sandbox tournant en root ; le nombre de skips varie avec
l'environnement d'exécution, pas le nombre total de tests), **couverture
99,46 %** (seuil CI 80 %), `mypy`/`ruff check`/`ruff format --check` verts
— chiffres de la session 45, vérifiés par une exécution réelle de la
suite.

Capacités en place :

- Encodeur/décodeur HEPv3 pur Python, source `tshark -T ek`, normaliseur
  UAUDP/UA3G/NOE, mode live (`--interface`) et relecture (`--pcap`).
- Payload sémantique structuré (UAUDP, endpoints, QoS, NOE) et
  corrélation stateless canonicalisée.
- Observabilité minimale (`stats.py`) et gestion des erreurs sans
  interruption du run.
- Détail par opcode et rythmique observée de
  `docs/noe-ua3g-homer-mapping.md#6ter` (opcodes UAUDP 16-23) désormais
  protégés par des tests de garde-fou (session 43, audit documentaire à
  backlog vide — voir [session 43](sessions/session-43.md)) : seul le
  total agrégé (163/993) l'était depuis la session 20.
- Keepalive HEP périodique en capture live.
- Arrêt propre sur `SIGINT` **et** `SIGTERM`.
- Collecteur HEP (`--hep-host`) joignable en IPv4, IPv6 ou nom DNS.
- Transport HEP configurable : UDP (défaut), TCP ou TCP+TLS
  (`--hep-transport`), vérification de certificat par défaut, CA
  personnalisée, bascule labo `--hep-tls-insecure`.
- Compression gzip optionnelle du payload (`--hep-compress-payload`,
  chunk HEP 0x0010) — **vérifiée non décodée par HOMER11 en l'état**
  (lecture directe de son code source, voir
  [hep-chunks.md](hep-chunks.md#compression-du-payload-chunk-0x0010)) ;
  désactivée par défaut, avertissement explicite si activée.
- Harnais de réception HEPv3 standalone (`tools/hep_receiver.py`).
- Retry avec backoff exponentiel sur échec d'envoi (`--hep-retries`,
  `--hep-retry-backoff`), sur les trois transports.
- Fréquence du log de progression configurable (`--stats-interval`).
- Sortie JSON structurée optionnelle (`--log-json-file`, implémentée en
  session 42, dernier candidat de l'audit de session 39) : sink loguru
  additionnel (`serialize=True`) en plus de stderr ; les enregistrements
  résumé de fin de run (`Stats.log_summary()`) et log de progression y
  portent en plus le dict complet de `Stats.to_dict()` sous
  `record.extra.stats` (via `logger.bind()`), jusqu'ici testé pour
  lui-même mais jamais consommé ailleurs — voir
  [session 42](sessions/session-42.md).
- Validation explicite du TOML (`ConfigError`) : table ou clé inconnue
  fait échouer le démarrage avec un message ciblé plutôt que d'être
  ignorée silencieusement.
- Notification systemd (`sd_notify`) : `READY=1`/`STOPPING=1`/
  `WATCHDOG=1` (`Type=notify`, watchdog optionnel via `WatchdogSec=`).
- CI durcie : contrôle de type statique (`mypy`, `disallow_untyped_defs`)
  et seuil de couverture minimal (`--cov-fail-under=80`), en complément
  de `ruff check`/`ruff format`.
- Nommage protocolaire officiel UAUDP/NOE/UA3G (`ua_opcode_names.py`) :
  opcodes, classes/méthodes/serveurs/événements/erreurs/propriétés NOE,
  sous-commandes IP Device Routing (opcode UA3G 0x13) et identifiants de
  paramètre poste (sous-commandes 0x09/0x02, 0x0A **et 0x11**) décodés en
  libellé humain quand une correspondance existe — sourcé depuis le
  dissecteur Wireshark officiel Alcatel-Lucent Enterprise, vérifié par
  recoupement avec les captures d'exemple du projet. La sous-commande
  0x0A (« Set Parameters Value », `ua3g.ip.set_param_req.parameter`)
  utilise une table dédiée (`UA3G_IP_DEVICE_ROUTING_SET_PARAMETER_NAMES`,
  40 entrées) distincte de celle des sous-commandes 0x09/0x02 malgré la
  proximité du nom de champ tshark, et porte elle aussi un doublement
  consécutif de chaque identifiant côté dissecteur (comme
  `ua3g.ip.cs.cmd02.parameter`, mais ici côté requête système) — voir
  [session 34](sessions/session-34.md). La sous-commande 0x11 (« Free
  Seating », `ua3g.ip.freeseating.parameter`) utilise elle aussi une
  table dédiée (`UA3G_IP_DEVICE_ROUTING_FREESEATING_PARAMETER_NAMES`, 4
  entrées seulement — `ip_device_routing_cmd_freeseating_vals[]`) et
  porte le même doublement consécutif, vérifié sur les deux fixtures
  (`[0, 0, 1, 1]` en ipv4, `[0, 0, 1, 1, 2, 2]` en ipv6) — voir
  [session 35](sessions/session-35.md).
- Archive de livraison canonique (`tools/package.py`, `make package`) :
  remplace tout zip manuel, exclusion par égalité exacte de segment de
  chemin plutôt que par motif glob approximatif — corrige la disparition
  récurrente de `.github/workflows/ci.yml` des archives livrées
  (sessions 17, 27, 35), désormais couverte par
  `tests/test_packaging.py` (archive réellement construite et inspectée
  à chaque run) — voir [session 36](sessions/session-36.md).
- Pipeline reconfirmé de bout en bout contre un vrai `tshark` en session
  37 (réseau disponible dans le sandbox) :
  `tests/test_real_tshark_integration.py` passe intégralement (64/339
  paquets pour les deux captures freeseating, 2544 reçus dont 993
  normalisés/envoyés pour `uaudp_ipv6` — chiffres identiques à ceux déjà
  documentés en session 24) — voir [session 37](sessions/session-37.md).
- Garde-fou de complétude automatisé pour le nommage IP Device Routing
  (`tests/test_ua3g_ip_device_routing_completeness.py`, session 38) :
  compare, via un vrai `tshark`, l'ensemble des valeurs `ua3g.ip`/
  `ua3g.ip.cs`/des quatre champs répétés d'identifiant de paramètre
  réellement présentes dans `sample_captures/*.pcap` aux tables de
  `ua_opcode_names.py` — remplace par un test permanent l'audit manuel
  répété aux sessions 34/35/37. Seule lacune connue et tolérée :
  l'identifiant de paramètre 0x0C (12) sur
  `ua3g.ip.get_param_req.parameter`/`ua3g.ip.cs.cmd02.parameter`, absent
  aussi de la table officielle Wireshark amont
  (`ip_device_routing_cmd_get_param_req_vals[]`, qui s'arrête à 0x0B) —
  déjà correctement résolu en `None` par `decode_names()`, ce n'est pas
  une lacune du projet. Ignoré (skip) si `tshark` n'est pas disponible,
  comme le reste de la famille `test_real_tshark_integration.py` — voir
  [session 38](sessions/session-38.md).
- Outillage géré par [uv](https://docs.astral.sh/uv/) (migration session
  44, demande explicite) : remplace la combinaison manuelle `python3 -m
  venv` + `pip install -e ".[dev]"` par `uv sync --extra dev` partout
  (`Makefile`, `install.sh`, CI). Le projet n'a jamais utilisé Poetry — le
  backend de build (`setuptools`, `pyproject.toml`) est inchangé. `uv.lock`
  ajouté au dépôt (figé, committé, inclus dans l'archive de livraison —
  `tests/test_packaging.py`) ; CI durcie avec `uv sync --locked` (échoue
  si le lock diverge de `pyproject.toml`, plutôt que de le régénérer
  silencieusement). 6 nouveaux tests de garde-fou dans
  `tests/test_ci_config.py` (CI/Makefile/install.sh utilisent bien `uv`,
  aucune commande de bootstrap pip/venv résiduelle) et `uv.lock` ajouté à
  la liste des fichiers de suivi protégés par `tests/test_packaging.py` —
  voir [session 44](sessions/session-44.md) et
  [docs/architecture.md](architecture.md#gestion-des-dépendances-et-de-lenvironnement-uv).
- Les deux documents exploratoires du projet
  (`docs/noe-ua3g-homer-mapping.md`, `docs/ua3g-call-signaling-decroche-
  numerotation.md`) ont désormais chacun leur constat empirique central
  protégé par des tests de garde-fou automatisés (§6ter du premier depuis
  la session 43, l'ensemble du second depuis la session 45 — audit
  n'ayant trouvé aucune inexactitude, contrairement à la session 43 qui
  avait comblé une lacune de couverture) plutôt que vérifié une fois puis
  laissé en prose — voir [session 45](sessions/session-45.md) et
  `tests/test_real_tshark_integration.py::test_ua3g_call_signaling_doc_*`.
- Audit du transport réseau (`sender.py`), sans dépendance externe.
  `UDPSender` connecte désormais sa socket au premier envoi (implémenté en
  session 40, voir ci-dessous) : un port UDP distant fermé peut être
  détecté (`ConnectionRefusedError`) là où l'ancien `sendto()` non connecté
  l'ignorait silencieusement — vérifié empiriquement, figé par
  `tests/test_sender.py::test_udp_sender_connect_detects_closed_remote_port_on_second_send`.
  `TCPSender` active désormais `TCP_NODELAY` sur sa socket dès `_connect()`
  (implémenté en session 41, voir ci-dessous) : Nagle, actif par défaut,
  retardait sinon l'émission de chaque paquet HEP déjà envoyé
  individuellement via `sendall()` — `setsockopt(socket.IPPROTO_TCP,
  socket.TCP_NODELAY, 1)` appelé sur la socket brute juste après
  `connect()`, avant l'éventuel enrobage TLS. Vérifié à la fois par mock
  (`setsockopt` appelé avec les bons arguments, avant tout enrobage TLS)
  et sur une vraie socket TCP loopback (`getsockopt` relit `1` après
  connexion). Sélection `ruff` élargie avec `TRY`/`S` (tryceratops,
  flake8-bandit) implémentée en session 40 : tous les signalements réels
  traités (voir `pyproject.toml`, `docs/architecture.md`) — voir
  [session 40](sessions/session-40.md) et [session 41](sessions/session-41.md).

## À faire — réalisable sans dépendance externe

Les deux candidats vérifiés issus de l'audit de la [session 39]
(sessions/session-39.md) sont désormais tous les deux implémentés :
« UDPSender : connect() » en [session 40](sessions/session-40.md),
« TCPSender : TCP_NODELAY » en [session 41](sessions/session-41.md) et
l'exploitation de `Stats.to_dict()` en [session 42]
(sessions/session-42.md) — voir « Capacités en place » ci-dessus pour les
trois.

**Aucun candidat vérifié ne reste dans cette section au sortir de la
session 42.** Conformément à
[`docs/session-protocol.md`](session-protocol.md), la session 43 a
justement pris ce chemin plutôt que de rester sans rien produire : audit
empirique de plusieurs affirmations documentaires (percentages/tables/
constantes de `docs/architecture.md`, `docs/hep-chunks.md`,
`ua_opcode_names.py`, `tools/hep_receiver.py`), toutes vérifiées exactes
sauf une lacune de couverture trouvée et comblée — voir
[session 43](sessions/session-43.md) et « Capacités en place » ci-dessus
pour le détail. La session 44 avait cette fois une demande explicite hors
backlog fonctionnel (migration d'outillage vers uv — voir « Capacités en
place » ci-dessus). La session 45 a repris la même procédure d'audit
documentaire (backlog toujours vide) sur le seul document exploratoire
encore signalé non audité, `docs/ua3g-call-signaling-decroche-
numerotation.md` : entièrement confirmé exact, et désormais protégé par
des tests — voir [session 45](sessions/session-45.md) et « Capacités en
place » ci-dessus. **Les deux documents exploratoires du projet ont
maintenant chacun leur constat empirique central protégé par un test
automatisé** ; aucune piste d'audit documentaire évidente ne reste
ouverte à ce jour — une future session à backlog vide devra soit en
trouver une nouvelle (relecture plus fine de `docs/architecture.md`,
`docs/hep-chunks.md`, `README.md`, ou tout autre fichier de suivi, à la
recherche d'une affirmation non encore recoupée avec le code/les
captures), soit accepter une demande explicite hors backlog comme la
session 44. Toujours aucun candidat de *nouvelle fonctionnalité métier*
vérifié à ce jour.

**Sélection `ruff` élargie, implémentée en session 40** (`TRY`/`S`,
absents auparavant de `pyproject.toml`) : essai réel en session 39
(`ruff check --select TRY,S src/ tools/` → 24 signalements, tous mineurs),
puis en session 40 : `TRY`/`S` activés, `TRY003` ignoré (justifié dans
`pyproject.toml` — pas de sous-classe d'exception dédiée pour des
`ValueError`/`TsharkError` internes simples), `S` exclu des tests
(`assert` y est l'idiome pytest, 751 occurrences légitimes mesurées à
l'activation en session 40 — 785 en session 43, croissance normale avec
les tests ajoutés depuis, comptage exact non maintenu ici au-delà de la
justification initiale puisqu'il continuera de croître à chaque nouveau
test), 3 `assert`
de narrowing remplacés par des gardes explicites (`if x is None: raise
RuntimeError(...)`, chacune testée — voir `tests/test_sdnotify.py` et
`tests/test_tshark_source.py`), 1 `TRY300` corrigé dans `sender.py`
(bloc `else`), 7 faux positifs `S104` (valeurs `"0.0.0.0"` neutres —
défauts de champs, pas des adresses d'écoute — voir `hep.py`,
`keepalive.py`, `normalizer.py`) annotés avec justification inline, 1
vrai `S104` sur `tools/hep_receiver.py` (adresse d'écoute d'un outil de
diagnostic local, délibéré) également annoté. `ruff check`/`ruff format
--check`/`mypy` verts.

**Candidat déjà écarté, reconfirmé en session 39** : la sous-commande
0x14 « Application Parameters » de IP Device Routing
(`ua3g.ip.appl.parameter`, table source `ip_device_routing_cmd_appl_vals[]`
— 3 entrées : 0x00 « Identifier », 0x01 « Enable », 0x02 « URL » — même
motif de dissection en boucle que les sous-commandes 0x0A/0x11 déjà
traitées). Rejeté en session 35 (absent des fixtures), reconfirmé en
session 37 (absent des captures complètes) et de nouveau en session 39
(`tshark -Y ua3g -T fields -e ua3g.opcode -e ua3g.ip` sur les trois
`.pcap` : toujours aucune valeur `0x14`) — à ne traiter que si une future
capture d'exemple le porte.

## Reporté sciemment — dépend d'une instance HOMER ou de trafic OXO réel

Items qui ne peuvent pas être validés dans l'état actuel du projet (pas
d'accès à un PABX Alcatel OXO en production, pas d'instance HOMER de
test) — voir le détail des raisons dans
[docs/noe-ua3g-homer-mapping.md](noe-ua3g-homer-mapping.md) :

- ~~Intégration Docker HOMER/heplify-server (docker-compose de démo)~~ —
  fait en issue #47 contre HOMER7 (heplify-server 1.60.9, homer-app
  1.5.22) : `deploy/homer/`. Reste non testé : HOMER11 lui-même (voir
  `docs/hep-chunks.md`).
- Mapping métier complet des opcodes UAUDP/NOE → **événements d'appel
  SIP** (INVITE/BYE/180/200...) — distinct du nommage protocolaire
  ci-dessus (désormais fait) : même avec les noms officiels, la
  correspondance temporelle entre un événement poste NOE et un message
  SIP côté trunk OXE reste une déduction non validée sans trafic OXO
  réel.
- Corrélation d'appel avec état partagé, inter-protocoles UA↔SIP (hors
  périmètre technique actuel : le pont ne fait que de la corrélation
  intra-UA, stateless).
