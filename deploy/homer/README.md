# Démo HOMER7 (issue #47)

Stack locale pour recevoir le HEP émis par `oxo-hep-bridge` : heplify-server
(collecteur), PostgreSQL (stockage) et homer-app (interface web).

```bash
cd deploy/homer
docker compose up -d          # ou : podman compose up -d
cd ../..
oxo-hep-bridge --config config/oxo-hep-bridge.homer-demo.toml
```

| Service        | Port hôte          | Rôle                                   |
| -------------- | ------------------ | -------------------------------------- |
| heplify-server | 9060/udp, 9060/tcp | HEP en UDP et TCP                      |
| heplify-server | 9061/tcp           | HEP en TLS (certificat auto-signé)     |
| homer-app      | 9080               | interface web, `admin` / `sipcapture`  |

Dans l'interface : Search, protocole **LOG** (`100_default`), plage horaire
« dernière heure ». Les paquets portent le `node_name` du pont dans
`captureId` et la clé de corrélation dans `sid` / `correlation_id`.

Démo locale uniquement : mots de passe par défaut, aucun volume persistant
(`docker compose down` efface tout).

## Captures d'exemple

```bash
B="oxo-hep-bridge --pcap-retime --hep-host 127.0.0.1 --node-name oxo-demo"
$B --pcap sample_captures/ua3g_freeseating_ipv4.pcap
$B --pcap sample_captures/ua3g_freeseating_ipv6.pcap
$B --pcap sample_captures/uaudp_ipv6.pcap --decode-as udp.port==32640,uaudp
# TCP / TLS
$B --pcap sample_captures/ua3g_freeseating_ipv4.pcap --hep-transport tcp
$B --pcap sample_captures/ua3g_freeseating_ipv4.pcap --hep-transport tls --hep-port 9061 --hep-tls-insecure
```

`--pcap-retime` est **indispensable** pour ces captures (2017-2018) : voir
plus bas.

## Résultats vérifiés (10/10/2026)

Contre heplify-server 1.60.9, PostgreSQL 15 et homer-app 1.5.22. Les images
sont celles du `compose.yml`, mais lancées une par une avec podman et
`--network=host` : le bac à sable de développement n'a pas de réseau
bridge. Le `compose.yml` lui-même est validé par `podman-compose config`
et par `tests/test_homer_demo.py`.

| Vérification | Résultat |
| --- | --- |
| `ua3g_freeseating_ipv4.pcap` (UDP) | 64 envoyés, 64 en base (`hep_proto_100_default`) |
| `ua3g_freeseating_ipv6.pcap` (UDP) | 339 envoyés, 339 en base |
| `uaudp_ipv6.pcap` (TCP, `--decode-as`) | 993 envoyés, 993 en base |
| UDP et TCP sur le même port 9060 | les deux reçus |
| TLS + `--hep-tls-insecure` | 64 reçus |
| TLS sans `--hep-tls-insecure` | refusé : `CERTIFICATE_VERIFY_FAILED` (attendu, certificat auto-signé) |
| Recherche homer-app (`/api/v3/search/call/data`, `100_default`) | paquets trouvés, `raw` = JSON du pont, `captureId` = `node_name` |
| Corrélation | 5 `sid` distincts sur les 3 captures, un par couple d'extrémités |
| **Sans `--pcap-retime`** | **0 en base** : `pq: no partition of relation "hep_proto_100_default" found for row` |
| **`--hep-compress-payload`** | **reçus (64 dans `heplify_packets_total`) mais 0 en base** |
| **Keepalive (`--keepalive-interval 2`, capture live)** | **reçus (compteur Prometheus) mais 0 en base** |

### Pourquoi ces trois cas n'arrivent pas en base

heplify-server n'insère un paquet de type ≥ 2 que si son payload **et** son
identifiant de corrélation (CID) sont non vides
([database/postgres.go](https://github.com/sipcapture/heplify-server/blob/master/database/postgres.go)) :

- **dates anciennes** : les tables `hep_proto_*` sont partitionnées par
  tranche de 2 h autour de la date du jour. Une capture de 2017 n'a pas de
  partition, d'où `--pcap-retime`, qui recale le premier paquet sur
  l'heure courante en conservant les écarts ;
- **payload compressé** (chunk 0x0010) : heplify-server ne le décode pas, le
  payload est vide et le paquet est abandonné sans erreur dans les journaux.
  Même limite que celle déjà relevée pour HOMER11 (`docs/hep-chunks.md`) :
  ne pas utiliser `--hep-compress-payload` avec HOMER ;
- **keepalive** : il n'a pas de Correlation ID (aucun flux réel). Il est
  compté par heplify-server (`heplify_packets_total{node_id=...}` sur le
  port Prometheus 9096), ce qui suffit pour superviser la présence du pont,
  mais il n'apparaît pas dans la recherche HOMER.
