#!/usr/bin/env python3
"""Configuration de oxo-hep-bridge.

Priorité de résolution (la plus forte gagne) :
    options CLI  >  variables d'environnement (OXOHEP_*)  >  fichier TOML  >  valeurs par défaut

Le chargement se fait en 3 passes qui mutent un `Config` construit avec les
valeurs par défaut : `apply_toml()` puis `apply_env()` puis, côté CLI, la
surcharge des arguments explicitement fournis par l'utilisateur.
"""

from __future__ import annotations

import os
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

from loguru import logger

from oxo_hep_bridge.i18n import _


class ConfigError(Exception):
    """Fichier TOML syntaxiquement valide mais sémantiquement fautif :
    table ou clé inconnue (typo probable dans `config/oxo-hep-bridge.toml`).

    Distinct des erreurs `tomllib.TOMLDecodeError` (syntaxe TOML invalide,
    déjà propagées telles quelles) : celle-ci couvre le cas — plus insidieux —
    d'un TOML syntaxiquement correct mais qui ne configure rien du tout parce
    qu'une clé est mal orthographiée ou mal placée (voir apply_toml())."""


@dataclass
class CaptureConfig:
    interface: str | None = None
    pcap: str | None = None
    bpf: str | None = None
    decode_as: list[str] = field(default_factory=list)
    # Pas de liste de champs par défaut : on laisse tshark sortir TOUS les
    # champs décodés (format doublement préfixé uaudp_uaudp_opcode). Une
    # liste -e restrictive change le format de sortie (clés simple-préfixe
    # uaudp_opcode au lieu de uaudp_uaudp_opcode, pas de structure "layers")
    # et omettrait les champs NOE dynamiques (variables selon le message).
    fields: list[str] = field(default_factory=list)
    tshark_path: str = "tshark"
    # Relecture --pcap : décale les horodatages HEP pour que le premier paquet
    # porte l'heure courante (écarts relatifs conservés). Sans cela, HOMER7
    # (heplify-server + PostgreSQL) rejette les paquets d'une capture ancienne :
    # « no partition of relation hep_proto_100_default found for row », les
    # partitions n'existant que autour de la date du jour (issue #47).
    pcap_retime: bool = False


@dataclass
class HepConfig:
    host: str = "127.0.0.1"
    port: int = 9060
    capture_agent_id: int = 2001
    proto_type: int = 100  # ProtoType.LOG
    auth_key: str | None = None
    node_name: str | None = None
    keepalive_interval: int = 0  # secondes ; 0 = désactivé
    transport: str = "udp"  # "udp" | "tcp" | "tls" (voir sender.TRANSPORTS)
    tls_verify: bool = True  # ignoré hors transport "tls" ; False = labo/certificat auto-signé
    tls_ca_file: str | None = None  # CA personnalisée optionnelle (transport "tls")
    compress_payload: bool = False  # gzip du payload (chunk 0x0010 au lieu de 0x000F)
    send_retries: int = 0  # tentatives supplémentaires sur échec d'envoi ; 0 = désactivé
    send_retry_backoff: float = 0.5  # délai de base (secondes), doublé à chaque tentative


@dataclass
class NormalizerConfig:
    correlation_field: str = ""


@dataclass
class LoggingConfig:
    level: str = "INFO"
    # Fréquence (en nombre de paquets HEP envoyés) du log de progression
    # pendant le run ("progression : N paquets envoyés..."). 500 par défaut
    # (comportement historique inchangé) ; <= 0 désactive ce log de
    # progression (seul le résumé de fin de run reste affiché).
    stats_interval: int = 500
    # Chemin de fichier optionnel : si renseigné, un sink loguru JSON Lines
    # (un objet JSON par ligne, `serialize=True` natif loguru) y est ajouté
    # en plus de la sortie stderr humaine habituelle — toute la
    # journalisation y est dupliquée en structuré, et les enregistrements
    # émis par Stats.log_summary()/le log de progression y portent en plus
    # le détail complet de Stats.to_dict() sous record.extra.stats. None
    # (défaut) = pas de sortie JSON, comportement historique inchangé.
    json_file: str | None = None


@dataclass
class Config:
    capture: CaptureConfig = field(default_factory=CaptureConfig)
    hep: HepConfig = field(default_factory=HepConfig)
    normalizer: NormalizerConfig = field(default_factory=NormalizerConfig)
    logging: LoggingConfig = field(default_factory=LoggingConfig)
    dry_run: bool = False

    # --- Construction ---

    @classmethod
    def load(cls, toml_path: str | Path | None = None) -> Config:
        """Construit la config en appliquant TOML puis environnement.

        Les options CLI doivent être appliquées séparément par l'appelant
        (cli.py), après cet appel, pour respecter la priorité CLI > env > TOML.
        """
        config = cls()
        if toml_path is not None:
            apply_toml(config, Path(toml_path))
        apply_env(config)
        return config

    @classmethod
    def from_env(cls) -> Config:
        """Conservé pour compatibilité : équivaut à load(toml_path=None)."""
        return cls.load(toml_path=None)


# Clés reconnues par table TOML, utilisées par _validate_toml_table() pour
# détecter une clé inconnue (typo) plutôt que de l'ignorer silencieusement.
# Tenues à jour manuellement en miroir des blocs `if "..." in ...` des
# fonctions `_apply_toml_*()` ci-dessous et de `apply_toml()` — pas de
# solution générique par introspection ici : les noms de clé TOML
# (snake_case) et les alias CLI/env divergent parfois du nom du champ
# dataclass, une simple liste explicite reste plus lisible qu'un mapping
# implicite fragile.
_CAPTURE_KEYS = frozenset(
    {"interface", "pcap", "bpf", "decode_as", "fields", "tshark_path", "pcap_retime"}
)
_HEP_KEYS = frozenset(
    {
        "host",
        "port",
        "capture_agent_id",
        "proto_type",
        "auth_key",
        "node_name",
        "keepalive_interval",
        "transport",
        "tls_verify",
        "tls_ca_file",
        "compress_payload",
        "send_retries",
        "send_retry_backoff",
    }
)
_NORMALIZER_KEYS = frozenset({"correlation_field"})
_LOGGING_KEYS = frozenset({"level", "stats_interval", "json_file"})
_KNOWN_TOML_TABLES = frozenset({"capture", "hep", "normalizer", "logging"})


def _validate_toml_table(data: dict, name: str, known_keys: frozenset[str]) -> dict:
    """Retourne `data[name]` comme table TOML validée (dict vide si absente).

    Lève `ConfigError` dans deux cas, tous deux des typos silencieuses avant
    ce correctif — le run démarrait avec des valeurs par défaut sans aucun
    avertissement :
    - `data[name]` existe mais n'est pas une table TOML (ex: `hep = "x"` au
      lieu de `[hep]` — clé écrite hors de sa section) ;
    - une clé de `data[name]` n'appartient pas à `known_keys` (ex: `hots`
      au lieu de `host` sous `[hep]`).
    """
    value = data.get(name, {})
    if not isinstance(value, dict):
        raise ConfigError(
            _(
                "[{name}] doit être une table TOML (ex: '[{name}]' suivi de "
                "'clé = valeur' sur les lignes suivantes) ; trouvé "
                "{type} — clé placée hors de sa section [{name}] ?"
            ).format(name=name, type=type(value).__name__)
        )
    unknown = set(value) - known_keys
    if unknown:
        raise ConfigError(
            _(
                "clé(s) TOML inconnue(s) sous [{name}] : {unknown} "
                "(clés valides : {valid}) — typo dans "
                "config/oxo-hep-bridge.toml ?"
            ).format(
                name=name, unknown=", ".join(sorted(unknown)), valid=", ".join(sorted(known_keys))
            )
        )
    return value


def _apply_toml_capture(config: Config, cap: dict) -> None:
    if "interface" in cap:
        config.capture.interface = cap["interface"]
    if "pcap" in cap:
        config.capture.pcap = cap["pcap"]
    if "bpf" in cap:
        config.capture.bpf = cap["bpf"]
    if "decode_as" in cap:
        config.capture.decode_as = list(cap["decode_as"])
    if "fields" in cap:
        config.capture.fields = list(cap["fields"])
    if "tshark_path" in cap:
        config.capture.tshark_path = cap["tshark_path"]
    if "pcap_retime" in cap:
        config.capture.pcap_retime = bool(cap["pcap_retime"])


def _apply_toml_hep(config: Config, hep: dict) -> None:
    if "host" in hep:
        config.hep.host = hep["host"]
    if "port" in hep:
        config.hep.port = int(hep["port"])
    if "capture_agent_id" in hep:
        config.hep.capture_agent_id = int(hep["capture_agent_id"])
    if "proto_type" in hep:
        config.hep.proto_type = int(hep["proto_type"])
    if "auth_key" in hep:
        config.hep.auth_key = hep["auth_key"]
    if "node_name" in hep:
        config.hep.node_name = hep["node_name"]
    if "keepalive_interval" in hep:
        config.hep.keepalive_interval = int(hep["keepalive_interval"])
    if "transport" in hep:
        config.hep.transport = hep["transport"]
    if "tls_verify" in hep:
        config.hep.tls_verify = bool(hep["tls_verify"])
    if "tls_ca_file" in hep:
        config.hep.tls_ca_file = hep["tls_ca_file"]
    if "compress_payload" in hep:
        config.hep.compress_payload = bool(hep["compress_payload"])
    if "send_retries" in hep:
        config.hep.send_retries = int(hep["send_retries"])
    if "send_retry_backoff" in hep:
        config.hep.send_retry_backoff = float(hep["send_retry_backoff"])


def apply_toml(config: Config, toml_path: Path) -> None:
    """Applique les valeurs d'un fichier TOML sur un Config existant (in-place).

    Silencieux si le fichier n'existe pas (le TOML est optionnel). Lève
    `tomllib.TOMLDecodeError` si le fichier existe mais n'est pas du TOML
    syntaxiquement valide (propagée telle quelle, message déjà explicite),
    et lève `ConfigError` si le TOML est syntaxiquement valide mais contient
    une table ou une clé inconnue — une simple table/clé mal orthographiée
    (ex: `[hep]` mal fermé, `hots` au lieu de `host`) était jusqu'ici ignorée
    silencieusement par `apply_toml()`/`_apply_toml_capture()`/
    `_apply_toml_hep()` (boucles `if "..." in table`) : le run démarrait
    avec la valeur par défaut du champ visé, sans aucun avertissement — un
    `[hep] hots = "10.0.0.5"` laissait par exemple le pont pointer vers
    `127.0.0.1` en silence. Le détail par table est délégué à
    `_apply_toml_capture()`/`_apply_toml_hep()` pour rester sous le seuil de
    statements par fonction (ruff PLR0915) — le nombre de champs ne cesse de
    croître au fil des fonctionnalités.
    """
    if not toml_path.exists():
        logger.debug("fichier de config TOML introuvable, ignoré : {}", toml_path)
        return
    with toml_path.open("rb") as f:
        data = tomllib.load(f)

    unknown_top_level = set(data) - _KNOWN_TOML_TABLES
    if unknown_top_level:
        raise ConfigError(
            _(
                "entrée(s) inconnue(s) au premier niveau du TOML : "
                "{unknown} (sections valides : "
                "{valid}) — clé écrite hors de "
                "sa section [table] ? (ex: 'host = ...' doit être sous [hep])"
            ).format(
                unknown=", ".join(sorted(unknown_top_level)),
                valid=", ".join(sorted(_KNOWN_TOML_TABLES)),
            )
        )

    cap = _validate_toml_table(data, "capture", _CAPTURE_KEYS)
    _apply_toml_capture(config, cap)

    hep = _validate_toml_table(data, "hep", _HEP_KEYS)
    _apply_toml_hep(config, hep)

    norm = _validate_toml_table(data, "normalizer", _NORMALIZER_KEYS)
    if "correlation_field" in norm:
        config.normalizer.correlation_field = norm["correlation_field"]

    log = _validate_toml_table(data, "logging", _LOGGING_KEYS)
    if "level" in log:
        config.logging.level = log["level"]
    if "stats_interval" in log:
        config.logging.stats_interval = int(log["stats_interval"])
    if "json_file" in log:
        config.logging.json_file = log["json_file"]

    logger.debug("config TOML chargée depuis {}", toml_path)


def _env_bool(value: str) -> bool:
    return value.strip().lower() in ("1", "true", "yes", "on")


def apply_env(config: Config) -> None:
    """Applique les variables d'environnement (préfixe OXOHEP_) sur un Config
    existant (in-place). Seules les variables réellement définies écrasent
    la valeur courante (TOML ou défaut)."""
    env = os.environ

    if v := env.get("OXOHEP_INTERFACE"):
        config.capture.interface = v
    if v := env.get("OXOHEP_PCAP"):
        config.capture.pcap = v
    if v := env.get("OXOHEP_PCAP_RETIME"):
        config.capture.pcap_retime = _env_bool(v)
    if v := env.get("OXOHEP_BPF"):
        config.capture.bpf = v
    if v := env.get("OXOHEP_DECODE_AS"):
        # Chaque règle --decode-as contient elle-même une virgule (syntaxe
        # tshark `champ==valeur,protocole`, ex: "udp.port==32640,uaudp") :
        # scinder sur "," casserait la première règle en deux fragments
        # invalides. On sépare donc plusieurs règles par ";" côté variable
        # d'environnement (contrairement au TOML, qui accepte une vraie
        # liste `decode_as = ["udp.port==32640,uaudp"]` sans ambiguïté).
        config.capture.decode_as = v.split(";")
    if v := env.get("OXOHEP_TSHARK_PATH"):
        config.capture.tshark_path = v

    if v := env.get("OXOHEP_HEP_HOST"):
        config.hep.host = v
    if v := env.get("OXOHEP_HEP_PORT"):
        config.hep.port = int(v)
    if v := env.get("OXOHEP_HEP_ID"):
        config.hep.capture_agent_id = int(v)
    if v := env.get("OXOHEP_PROTO_TYPE"):
        config.hep.proto_type = int(v)
    if v := env.get("OXOHEP_HEP_PASS"):
        config.hep.auth_key = v
    if v := env.get("OXOHEP_NODE_NAME"):
        config.hep.node_name = v
    if v := env.get("OXOHEP_KEEPALIVE_INTERVAL"):
        config.hep.keepalive_interval = int(v)
    if v := env.get("OXOHEP_HEP_TRANSPORT"):
        config.hep.transport = v
    if v := env.get("OXOHEP_HEP_TLS_VERIFY"):
        config.hep.tls_verify = _env_bool(v)
    if v := env.get("OXOHEP_HEP_TLS_CA_FILE"):
        config.hep.tls_ca_file = v
    if v := env.get("OXOHEP_HEP_COMPRESS_PAYLOAD"):
        config.hep.compress_payload = _env_bool(v)
    if v := env.get("OXOHEP_HEP_SEND_RETRIES"):
        config.hep.send_retries = int(v)
    if v := env.get("OXOHEP_HEP_SEND_RETRY_BACKOFF"):
        config.hep.send_retry_backoff = float(v)

    if v := env.get("OXOHEP_CORRELATION_FIELD"):
        config.normalizer.correlation_field = v

    if v := env.get("OXOHEP_LOG_LEVEL"):
        config.logging.level = v
    if v := env.get("OXOHEP_STATS_INTERVAL"):
        config.logging.stats_interval = int(v)
    if v := env.get("OXOHEP_LOG_JSON_FILE"):
        config.logging.json_file = v

    if v := env.get("OXOHEP_DRY_RUN"):
        config.dry_run = _env_bool(v)
