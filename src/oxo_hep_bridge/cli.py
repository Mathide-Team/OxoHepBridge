#!/usr/bin/env python3
"""Point d'entrée CLI de oxo-hep-bridge.

Priorité de résolution de la config :
    options CLI (explicitement fournies) > variables d'environnement (OXOHEP_*)
    > fichier TOML (--config) > valeurs par défaut

Pour respecter cette priorité, les arguments CLI n'écrasent la config que s'ils
ont été explicitement passés par l'utilisateur (sinon un default d'argparse
écraserait une valeur venue de l'environnement ou du TOML).
"""

from __future__ import annotations

import argparse
import signal
import sys
import tomllib

from loguru import logger

from oxo_hep_bridge.bridge import Bridge
from oxo_hep_bridge.config import Config, ConfigError
from oxo_hep_bridge.i18n import _
from oxo_hep_bridge.sdnotify import SdNotifier, WatchdogScheduler, resolve_watchdog_interval
from oxo_hep_bridge.sender import TRANSPORTS


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="oxo-hep-bridge",
        description=_("Pont Alcatel OXO (UAUDP/UA3G/NOE) vers HOMER via tshark -T ek + HEPv3"),
    )
    p.add_argument(
        "--config",
        help=_("Chemin vers le fichier de configuration TOML (ex: config/oxo-hep-bridge.toml)"),
    )
    src = p.add_mutually_exclusive_group(required=False)
    src.add_argument("--interface", help=_("Interface réseau pour capture live (ex: eth0)"))
    src.add_argument("--pcap", help=_("Fichier .pcap à relire hors-ligne"))
    p.add_argument("--bpf", help=_('Filtre BPF (ex: "udp port 32640")'))
    p.add_argument(
        "--pcap-retime",
        action="store_true",
        default=None,  # None = non fourni ; on ne veut pas écraser env/TOML
        help=_(
            "Avec --pcap : horodate le premier paquet à l'heure courante (écarts conservés), pour HOMER7"
        ),
    )
    p.add_argument(
        "--decode-as",
        action="append",
        default=None,  # None = non fourni ; on ne veut pas écraser env/TOML
        help=_("Force le décodage tshark (ex: udp.port==32640,uaudp). Répétable."),
    )
    p.add_argument(
        "--tshark-path",
        default=None,
        help=_("Chemin vers l'exécutable tshark (défaut: 'tshark', résolu via PATH)"),
    )

    p.add_argument("--hep-host", default=None)
    p.add_argument("--hep-port", type=int, default=None)
    p.add_argument("--hep-id", type=int, default=None, help=_("Capture agent ID HEP"))
    p.add_argument("--proto-type", type=int, default=None, help=_("HEP protocol type (100=LOG)"))
    p.add_argument(
        "--hep-pass",
        "--hep-auth-key",
        dest="hep_pass",
        default=None,
        help=_("Clé d'authentification HEP (si configurée côté heplify-server NodePW)"),
    )
    p.add_argument(
        "--node-name",
        default=None,
        help=_("Nom du nœud / group id HEP (chunk 0x0013), visible dans HOMER"),
    )
    p.add_argument(
        "--keepalive-interval",
        type=int,
        default=None,
        help=(
            _(
                "Intervalle en secondes entre deux paquets HEP keepalive envoyés "
                "en capture live (0 ou absent = désactivé)"
            )
        ),
    )
    p.add_argument(
        "--hep-transport",
        dest="hep_transport",
        default=None,
        choices=list(TRANSPORTS),
        help=_("Transport HEP vers le collecteur : udp (défaut), tcp ou tls"),
    )
    p.add_argument(
        "--hep-tls-insecure",
        dest="hep_tls_insecure",
        action="store_true",
        default=False,
        help=(
            _(
                "Désactive la vérification du certificat serveur en transport tls "
                "(nom d'hôte + chaîne de confiance) — labo/certificat auto-signé "
                "uniquement, jamais en production"
            )
        ),
    )
    p.add_argument(
        "--hep-tls-ca-file",
        dest="hep_tls_ca_file",
        default=None,
        help=_("Fichier CA personnalisé pour vérifier le certificat du collecteur (transport tls)"),
    )
    p.add_argument(
        "--hep-compress-payload",
        dest="hep_compress_payload",
        action="store_true",
        default=False,
        help=(
            _(
                "Compresse le payload HEP (gzip, chunk 0x0010 au lieu de 0x000F). "
                "ATTENTION : non décodé par HOMER11/heplify-server à ce jour — "
                "n'activer que si le collecteur cible supporte explicitement ce chunk"
            )
        ),
    )

    p.add_argument(
        "--hep-retries",
        dest="hep_retries",
        type=int,
        default=None,
        help=(
            _(
                "Nombre de tentatives supplémentaires sur échec d'envoi HEP "
                "(UDP, TCP ou TLS), avec backoff exponentiel entre chaque essai "
                "(0/absent = désactivé, comportement inchangé)"
            )
        ),
    )
    p.add_argument(
        "--hep-retry-backoff",
        dest="hep_retry_backoff",
        type=float,
        default=None,
        help=(
            _(
                "Délai de base en secondes avant la 1re nouvelle tentative "
                "(doublé à chaque tentative suivante), sans effet si "
                "--hep-retries n'est pas positionné (défaut : 0.5)"
            )
        ),
    )

    p.add_argument(
        "--correlation-field",
        default=None,
        help=_("Champ tshark à utiliser comme correlation_id"),
    )

    p.add_argument(
        "--dry-run",
        action="store_true",
        help=_("N'envoie rien, encode et logge seulement"),
    )
    p.add_argument(
        "--log-level",
        default=None,
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
    )
    p.add_argument(
        "--stats-interval",
        dest="stats_interval",
        type=int,
        default=None,
        help=(
            _(
                "Fréquence (en paquets HEP envoyés) du log de progression "
                "pendant le run (défaut : 500 ; <= 0 désactive ce log, seul le "
                "résumé de fin de run reste affiché)"
            )
        ),
    )
    p.add_argument(
        "--log-json-file",
        dest="log_json_file",
        default=None,
        help=(
            _(
                "Chemin de fichier : ajoute une sortie JSON Lines structurée "
                "(en plus de stderr, serialize=True loguru) ; les enregistrements "
                "résumé/progression y portent le détail complet de Stats.to_dict() "
                "sous record.extra.stats (absent/vide = désactivé)"
            )
        ),
    )
    return p


def _apply_cli_args(config: Config, args: argparse.Namespace) -> None:
    """Applique uniquement les arguments CLI explicitement fournis (non-None)."""
    if args.interface is not None:
        config.capture.interface = args.interface
    if args.pcap is not None:
        config.capture.pcap = args.pcap
    if args.bpf is not None:
        config.capture.bpf = args.bpf
    if args.pcap_retime is not None:
        config.capture.pcap_retime = args.pcap_retime
    if args.decode_as is not None:
        config.capture.decode_as = args.decode_as
    if args.tshark_path is not None:
        config.capture.tshark_path = args.tshark_path

    if args.hep_host is not None:
        config.hep.host = args.hep_host
    if args.hep_port is not None:
        config.hep.port = args.hep_port
    if args.hep_id is not None:
        config.hep.capture_agent_id = args.hep_id
    if args.proto_type is not None:
        config.hep.proto_type = args.proto_type
    if args.hep_pass is not None:
        config.hep.auth_key = args.hep_pass
    if args.node_name is not None:
        config.hep.node_name = args.node_name
    if args.keepalive_interval is not None:
        config.hep.keepalive_interval = args.keepalive_interval
    if args.hep_transport is not None:
        config.hep.transport = args.hep_transport
    if args.hep_tls_ca_file is not None:
        config.hep.tls_ca_file = args.hep_tls_ca_file
    # --hep-tls-insecure est un bool flag à sens unique (comme --dry-run) :
    # sa présence force tls_verify à False, son absence préserve la valeur
    # venue du TOML/de l'environnement (pas de --hep-tls-secure pour ré-activer
    # explicitement depuis la CLI une vérification déjà désactivée ailleurs).
    if args.hep_tls_insecure:
        config.hep.tls_verify = False
    # --hep-compress-payload est un bool flag à sens unique, comme --dry-run :
    # sa présence active la compression, son absence préserve ce que le
    # TOML/l'environnement ont déjà positionné (pas de flag CLI pour la
    # désactiver explicitement si le TOML l'a déjà activée).
    config.hep.compress_payload = args.hep_compress_payload or config.hep.compress_payload
    if args.hep_retries is not None:
        config.hep.send_retries = args.hep_retries
    if args.hep_retry_backoff is not None:
        config.hep.send_retry_backoff = args.hep_retry_backoff

    if args.correlation_field is not None:
        config.normalizer.correlation_field = args.correlation_field

    if args.log_level is not None:
        config.logging.level = args.log_level
    if args.stats_interval is not None:
        config.logging.stats_interval = args.stats_interval
    if args.log_json_file is not None:
        config.logging.json_file = args.log_json_file

    # --dry-run est un bool flag (présent => True, absent => False)
    config.dry_run = args.dry_run or config.dry_run


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    # Charger le TOML + les variables d'environnement. Erreur explicite (pas
    # de traceback brute) sur un TOML syntaxiquement invalide ou sur une
    # table/clé inconnue (typo) : avant ce garde-fou, une clé mal orthographiée
    # sous [hep] était ignorée en silence et le run démarrait quand même, avec
    # les valeurs par défaut du champ visé — un mauvais réglage indétectable
    # sans relire le TOML ligne à ligne. Code de retour 2, comme les erreurs
    # d'arguments argparse (`build_parser().error()`), pour rester cohérent :
    # dans les deux cas il s'agit d'une erreur d'usage/config, pas d'un échec
    # du run lui-même (réservé au bloc try/except autour de bridge.run()).
    try:
        config = Config.load(toml_path=args.config)
    except ConfigError as exc:
        logger.error(_("configuration TOML invalide ({}) : {}"), args.config, exc)
        return 2
    except tomllib.TOMLDecodeError as exc:
        logger.error(_("fichier TOML syntaxiquement invalide ({}) : {}"), args.config, exc)
        return 2

    # Surcharge par les arguments CLI explicites uniquement
    _apply_cli_args(config, args)

    if not config.capture.interface and not config.capture.pcap:
        build_parser().error("--interface ou --pcap est requis")

    # loguru : reconfigurer le niveau choisi
    logger.remove()
    logger.add(sys.stderr, level=config.logging.level)

    # Sortie JSON Lines structurée optionnelle, en plus de stderr : un objet
    # JSON par ligne (serialize=True, format natif loguru), qui inclut pour
    # chaque enregistrement le dict complet lié par Stats.log_summary()/le
    # log de progression de Bridge.run() sous record.extra.stats (voir
    # stats.py, bridge.py) — exploite Stats.to_dict(), jusqu'ici testé pour
    # lui-même mais jamais consommé par le reste du pont (voir docs/roadmap.md).
    if config.logging.json_file:
        logger.add(config.logging.json_file, serialize=True, level=config.logging.level)

    # tls_verify/tls_ca_file n'ont d'effet qu'en transport "tls" : avertir
    # plutôt qu'ignorer silencieusement une combinaison probablement fautive
    # (ex: --hep-tls-ca-file sans --hep-transport tls, transport resté à udp).
    if config.hep.transport != "tls" and (not config.hep.tls_verify or config.hep.tls_ca_file):
        logger.warning(
            _(
                "hep.tls_verify/hep.tls_ca_file n'ont d'effet qu'avec transport=tls "
                "(transport actuel : {!r})"
            ),
            config.hep.transport,
        )

    # compress_payload émet le chunk HEP COMPRESSED_PAYLOAD (0x0010) à la
    # place de PAYLOAD (0x000F, chunk obligatoire décodé par tous les
    # collecteurs HEP). Ce chunk optionnel n'est PAS décodé par HOMER11
    # (src/decoder/decoder.go — sa liste de chunks connus s'arrête à
    # NodeName 0x0013, tout chunk inconnu tombe dans un `default:` muet) :
    # activer cette option contre un collecteur qui ne le supporte pas
    # revient à perdre silencieusement le payload de chaque paquet envoyé,
    # pas juste une dégradation mineure — d'où un avertissement explicite
    # plutôt qu'un simple mot dans la doc.
    if config.hep.compress_payload:
        logger.warning(
            _(
                "hep.compress_payload=true : le chunk HEP COMPRESSED_PAYLOAD (0x0010) "
                "n'est décodé que par un collecteur qui le supporte explicitement — "
                "HOMER11/heplify-server ne le décodent pas nativement à ce jour et "
                "le payload de chaque paquet serait alors perdu côté collecteur. "
                "Ne pas activer sans avoir vérifié le support du collecteur cible."
            )
        )

    # Gestion propre de Ctrl-C (SIGINT) et de l'arrêt systemd (SIGTERM) : on
    # ferme proprement le subprocess tshark, le sender et le keepalive plutôt
    # que de laisser le process se faire tuer brutalement. `systemctl stop`
    # envoie SIGTERM par défaut (voir systemd/oxo-hep-bridge.service, pas de
    # KillSignal custom) : sans ce handler, seul Ctrl-C déclenchait un arrêt
    # propre et un `systemctl stop`/redémarrage de service coupait le run
    # sans résumé de stats ni fermeture de socket.
    bridge = Bridge(config)

    _SHUTDOWN_SIGNALS = (signal.SIGINT, signal.SIGTERM)

    def _request_shutdown(signum: int, frame: object) -> None:
        raise KeyboardInterrupt

    original_handlers = {sig: signal.getsignal(sig) for sig in _SHUTDOWN_SIGNALS}
    for sig in _SHUTDOWN_SIGNALS:
        signal.signal(sig, _request_shutdown)

    # Notification systemd (sd_notify) : no-op silencieux hors service
    # systemd (NOTIFY_SOCKET absent) — voir sdnotify.py pour le détail du
    # protocole et les limites de ce que le watchdog détecte réellement.
    # `ready()` est envoyé juste avant de démarrer le run, une fois la
    # configuration validée et Bridge construit avec succès : c'est la
    # définition de « démarrage terminé » pour ce process (le lancement du
    # subprocess tshark, lui, a lieu à l'intérieur de bridge.run()).
    notifier = SdNotifier()
    watchdog = WatchdogScheduler(notifier, resolve_watchdog_interval())
    if notifier.enabled:
        logger.debug("notification systemd active (NOTIFY_SOCKET détecté)")
        if watchdog.enabled:
            logger.debug(
                "watchdog systemd actif (WatchdogSec côté unité systemd, WATCHDOG_USEC={}s)",
                watchdog.watchdog_interval,
            )
    watchdog.start()
    notifier.ready()

    try:
        return bridge.run()
    except KeyboardInterrupt:
        logger.warning(_("Arrêt demandé (SIGINT/SIGTERM), fermeture du subprocess tshark..."))
        return 130
    except Exception as exc:
        logger.exception(_("Erreur fatale pendant l'exécution : {}"), exc)
        return 1
    finally:
        notifier.stopping()
        watchdog.stop()
        for sig, handler in original_handlers.items():
            signal.signal(sig, handler)


if __name__ == "__main__":
    raise SystemExit(main())
