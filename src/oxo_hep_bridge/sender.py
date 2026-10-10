#!/usr/bin/env python3
"""Couche d'envoi HEP injectable.

Séparée de la logique de bridge pour permettre les tests unitaires sans
ouvrir de socket réseau. `NullSender` (dry-run) ne fait rien et logge le
paquet décodé à la place.
"""

from __future__ import annotations

import contextlib
import socket
import ssl
import time
from collections.abc import Callable
from ipaddress import AddressValueError

from loguru import logger

from oxo_hep_bridge.hep import HepPacket, encode
from oxo_hep_bridge.i18n import _

TRANSPORTS = ("udp", "tcp", "tls")


def _retry_delays(retries: int, backoff: float) -> list[float]:
    """Calcule la séquence de délais (secondes) entre tentatives.

    Backoff exponentiel simple : `backoff * 2**n` pour la n-ième nouvelle
    tentative (n = 0, 1, 2...), sans jitter (pas nécessaire ici : un seul
    pont par instance OXO, pas de troupeau d'agents synchronisés qui
    justifierait de désynchroniser les retries). `retries=0` (défaut)
    donne une liste vide : aucune tentative supplémentaire, comportement
    inchangé par rapport à avant cette fonctionnalité.
    """
    return [backoff * (2**attempt) for attempt in range(retries)]


def _send_with_retry(
    *,
    send_once: Callable[[], None],
    close: Callable[[], None],
    retries: int,
    retry_backoff: float,
    sleep: Callable[[float], None],
    host: str,
    port: int,
    label: str = "",
) -> tuple[bool, int]:
    """Exécute `send_once()` avec retry/backoff exponentiel sur échec.

    Partagée par `UDPSender` et `TCPSender` (même politique de retry pour les
    deux transports). `send_once` et `close` sont injectés plutôt que de
    dépendre d'un sender concret, pour rester testable isolément. Retourne
    `(succès, nombre de tentatives supplémentaires effectivement consommées)`
    plutôt que de muter un compteur par effet de bord — l'appelant l'ajoute
    à son propre `retry_count` cumulé.
    """
    delays = _retry_delays(retries, retry_backoff)
    used = 0
    suffix = f" ({label})" if label else ""
    for attempt, delay in enumerate([0.0, *delays]):
        if delay:
            used += 1
            sleep(delay)
        try:
            send_once()
        except (OSError, AddressValueError) as exc:
            # Referme la socket : un échec de résolution DNS transitoire ou un
            # changement d'adresse côté collecteur doit pouvoir être retenté
            # proprement plutôt que de rester bloqué sur une socket/famille
            # figée pour tout le run.
            close()
            remaining = len(delays) - attempt
            if remaining <= 0:
                logger.error(
                    _("Échec d'envoi HEP vers {}:{}{} après {} tentative(s) : {}"),
                    host,
                    port,
                    suffix,
                    attempt + 1,
                    exc,
                )
                return False, used
            logger.warning(
                _(
                    "Échec d'envoi HEP vers {}:{}{} (tentative {}/{}), nouvel essai dans {:.2f}s : {}"
                ),
                host,
                port,
                suffix,
                attempt + 1,
                len(delays) + 1,
                delays[attempt],
                exc,
            )
        else:
            return True, used
    return False, used  # inatteignable (la boucle retourne toujours), garde de type


def _resolve_destination(
    host: str, port: int, socktype: int = socket.SOCK_DGRAM
) -> tuple[socket.AddressFamily, tuple]:
    """Résout `host:port` en (famille de socket, sockaddr) via `getaddrinfo`.

    `heplify-server`/HOMER peut être joint par une adresse IPv4, une adresse
    IPv6 (littérale ou avec zone id) ou un nom d'hôte DNS résolvant vers l'une
    ou l'autre — `getaddrinfo` couvre les trois cas uniformément, plutôt qu'une
    détection `ipaddress.ip_address()` qui échouerait sur un nom d'hôte. Seul
    le premier résultat est utilisé (suffisant pour un collecteur HEP mono-IP ;
    pas de bascule vers une 2e adresse en cas d'échec, cohérent avec le
    comportement sans état du sender). `socktype` distingue UDP (`SOCK_DGRAM`,
    utilisé par `UDPSender`) de TCP/TLS (`SOCK_STREAM`, utilisé par
    `TCPSender`) : `getaddrinfo` peut renvoyer des résultats différents selon
    le type de socket demandé.
    """
    infos = socket.getaddrinfo(host, port, type=socktype)
    family, _socktype, _proto, _canonname, sockaddr = infos[0]
    return family, sockaddr


class Sender:
    """Interface commune pour les expéditeurs de paquets HEP.

    `retry_count` et `close()` ont une implémentation par défaut ici (plutôt
    que d'être absents de la classe de base) pour que `Bridge.run()` puisse
    les utiliser uniformément sur n'importe quel sender — y compris
    `NullSender` ou un sender factice de test — sans `hasattr()`/`getattr()`
    au point d'appel. Avant ce correctif, `bridge.py` testait dynamiquement
    la présence de ces deux attributs : un pattern invisible pour un
    contrôle de type statique (mypy ne fait pas de narrowing sur `hasattr()`
    pour une classe nominale), corrigé ici à la racine plutôt que contourné
    par des `# type: ignore` au site d'appel.
    """

    retry_count: int = 0

    def send(self, packet: HepPacket) -> bool:
        """Envoie un paquet HEP. Retourne True si l'envoi a réussi, False sinon."""
        raise NotImplementedError

    def close(self) -> None:
        """Libère les ressources réseau du sender, si applicable.

        No-op par défaut (ex: `NullSender`, qui n'ouvre aucune socket, ou un
        sender factice de test) ; `UDPSender`/`TCPSender` la surchargent pour
        fermer effectivement leur socket."""


class NullSender(Sender):
    """Mode dry-run : encode le paquet (pour valider l'encodeur) mais ne l'envoie pas."""

    def __init__(self, compress: bool = False) -> None:
        self.compress = compress

    def send(self, packet: HepPacket) -> bool:
        encoded = encode(packet, compress=self.compress)
        logger.info(
            _("[dry-run] HEP encoded ({} octets{}) proto_type={} correlation_id={!r}"),
            len(encoded),
            ", compressé" if self.compress else "",
            packet.proto_type,
            packet.correlation_id,
        )
        return True


class UDPSender(Sender):
    """Envoie les paquets HEP encodés via UDP vers le collecteur heplify-server.

    Le collecteur peut être désigné par une adresse IPv4, une adresse IPv6
    (littérale ou nom d'hôte résolvant en AAAA) — la famille de socket
    (`AF_INET`/`AF_INET6`) est déterminée par résolution (`getaddrinfo`) au
    premier envoi plutôt que fixée en dur à `AF_INET`, sans quoi `sendto()`
    échouait silencieusement (`OSError`) sur tout `--hep-host` IPv6.

    La socket est `connect()`ée (voir `_connect()`) pour permettre au noyau
    de remonter un `ConnectionRefusedError` si le port distant est fermé —
    détection impossible sur une socket UDP non connectée (session 40).
    """

    def __init__(
        self,
        host: str,
        port: int,
        compress: bool = False,
        *,
        retries: int = 0,
        retry_backoff: float = 0.5,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self.host = host
        self.port = port
        self.compress = compress
        self.retries = retries
        self.retry_backoff = retry_backoff
        self._sleep = sleep
        self.retry_count = 0  # cumulé sur la durée de vie du sender, pour les stats
        self._sock: socket.socket | None = None
        self._sockaddr: tuple = ()  # toujours réaffecté par _connect() avant tout envoi

    def _connect(self) -> socket.socket:
        if self._sock is not None:
            return self._sock
        family, sockaddr = _resolve_destination(self.host, self.port, socket.SOCK_DGRAM)
        sock = socket.socket(family, socket.SOCK_DGRAM)
        # connect() sur une socket UDP ne déclenche aucune poignée de main
        # (rien ne part sur le réseau) : il fixe seulement la destination
        # par défaut au niveau noyau. Bénéfice concret, vérifié
        # empiriquement (session 39/40) : un envoi ultérieur vers un port
        # distant fermé peut alors remonter un ConnectionRefusedError (ICMP
        # « port unreachable » associé à cette socket connectée) —
        # impossible sur une socket non connectée, qui ignore silencieusement
        # ce même ICMP. L'envoi lui-même reste sendto() (inchangé) : une
        # socket connectée continue de l'accepter, avec le même bénéfice de
        # détection (vérifié empiriquement). Voir
        # docs/architecture.md#transport-hep--udp-tcp-tls.
        sock.connect(sockaddr)
        self._sock = sock
        self._sockaddr = sockaddr
        return self._sock

    def _send_once(self, encoded: bytes) -> None:
        sock = self._connect()
        sock.sendto(encoded, self._sockaddr)

    def send(self, packet: HepPacket) -> bool:
        encoded = encode(packet, compress=self.compress)
        ok, used = _send_with_retry(
            send_once=lambda: self._send_once(encoded),
            close=self.close,
            retries=self.retries,
            retry_backoff=self.retry_backoff,
            sleep=self._sleep,
            host=self.host,
            port=self.port,
        )
        self.retry_count += used
        return ok

    def close(self) -> None:
        if self._sock is not None:
            self._sock.close()
            self._sock = None
        self._sockaddr = ()


class TCPSender(Sender):
    """Envoie les paquets HEP encodés via TCP, en clair ou sous TLS, vers le
    collecteur heplify-server.

    `heplify-server` expose un listener TCP et un listener TLS distincts de
    son listener UDP (`HEPTCPAddr`/`HEPTLSAddr`), utiles derrière un pare-feu
    qui bloque l'UDP sortant, ou pour chiffrer le trafic HEP en transit (le
    payload transporte des extraits de trafic OXO). Aucun framing
    supplémentaire n'est nécessaire côté client : chaque paquet HEPv3 encodé
    porte déjà sa longueur totale dans les 6 premiers octets (voir hep.py),
    ce qui suffit à délimiter les paquets sur le flux TCP — les paquets
    encodés sont donc envoyés tels quels, à la suite les uns des autres, sur
    une connexion ouverte une fois puis réutilisée (comme `UDPSender` avec sa
    socket), jusqu'à un échec ou un `close()` explicite.

    `TCP_NODELAY` est activé sur la socket dès `_connect()` (session 41) :
    l'algorithme de Nagle, actif par défaut, retarderait sinon l'émission de
    chaque petit paquet HEP en attendant soit un accusé de réception, soit
    d'accumuler assez de données pour un segment plein — un compromis pensé
    pour un flux d'écriture continu, pas pour des paquets HEP déjà envoyés
    un par un via `sendall()`.
    """

    def __init__(
        self,
        host: str,
        port: int,
        *,
        tls: bool = False,
        tls_verify: bool = True,
        tls_ca_file: str | None = None,
        compress: bool = False,
        retries: int = 0,
        retry_backoff: float = 0.5,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self.host = host
        self.port = port
        self.tls = tls
        self.tls_verify = tls_verify
        self.tls_ca_file = tls_ca_file
        self.compress = compress
        self.retries = retries
        self.retry_backoff = retry_backoff
        self._sleep = sleep
        self.retry_count = 0  # cumulé sur la durée de vie du sender, pour les stats
        self._sock: socket.socket | ssl.SSLSocket | None = None

    def _build_tls_context(self) -> ssl.SSLContext:
        """Construit le contexte TLS client.

        `tls_verify=False` désactive la vérification du certificat serveur
        (nom d'hôte + chaîne de confiance) : utile en labo contre un
        heplify-server avec un certificat auto-signé, jamais recommandé en
        production (`--hep-tls-insecure`/`tls_verify = false` doit rester un
        choix explicite). `tls_ca_file`, s'il est fourni, est chargé dans les
        deux cas — même non vérifié, un contexte peut avoir une CA connue
        chargée sans que `check_hostname`/`verify_mode` l'exploitent.
        """
        if self.tls_verify:
            return ssl.create_default_context(cafile=self.tls_ca_file)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        if self.tls_ca_file:
            context.load_verify_locations(cafile=self.tls_ca_file)
        return context

    def _connect(self) -> socket.socket | ssl.SSLSocket:
        if self._sock is not None:
            return self._sock
        family, sockaddr = _resolve_destination(self.host, self.port, socket.SOCK_STREAM)
        raw_sock = socket.socket(family, socket.SOCK_STREAM)
        try:
            raw_sock.connect(sockaddr)
            # Désactive l'algorithme de Nagle : chaque paquet HEP est déjà
            # envoyé individuellement via sendall() (jamais accumulé en
            # buffer applicatif), Nagle ne fait donc qu'ajouter jusqu'à
            # ~40ms de latence en attendant un accusé de réception avant
            # d'émettre un petit paquet — coût pur pour un flux de
            # supervision quasi temps réel, sans bénéfice de groupage
            # puisqu'il n'y a rien à grouper. Positionné sur la socket
            # brute avant l'éventuel enrobage TLS : TCP_NODELAY est une
            # option de la couche transport, `ssl.SSLSocket` délègue à la
            # socket sous-jacente (vérifié empiriquement, voir
            # tests/test_sender.py).
            raw_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            if self.tls:
                context = self._build_tls_context()
                self._sock = context.wrap_socket(raw_sock, server_hostname=self.host)
            else:
                self._sock = raw_sock
        except Exception:
            # connect() ou la poignée de main TLS a échoué : ne pas laisser un
            # descripteur de socket partiellement ouvert fuiter, l'appelant
            # (send()) retentera une connexion propre au prochain envoi.
            raw_sock.close()
            raise
        return self._sock

    def _send_once(self, encoded: bytes) -> None:
        sock = self._connect()
        sock.sendall(encoded)

    def send(self, packet: HepPacket) -> bool:
        # ssl.SSLError (poignée de main TLS incluse) est une sous-classe
        # d'OSError, déjà couverte par _send_with_retry sans except dédié.
        encoded = encode(packet, compress=self.compress)
        ok, used = _send_with_retry(
            send_once=lambda: self._send_once(encoded),
            close=self.close,
            retries=self.retries,
            retry_backoff=self.retry_backoff,
            sleep=self._sleep,
            host=self.host,
            port=self.port,
            label="tls" if self.tls else "tcp",
        )
        self.retry_count += used
        return ok

    def close(self) -> None:
        if self._sock is not None:
            with contextlib.suppress(OSError):
                self._sock.close()
            self._sock = None


def make_sender(
    host: str,
    port: int,
    *,
    dry_run: bool = False,
    transport: str = "udp",
    tls_verify: bool = True,
    tls_ca_file: str | None = None,
    compress: bool = False,
    retries: int = 0,
    retry_backoff: float = 0.5,
) -> Sender:
    """Construit le sender approprié.

    `dry_run` court-circuite toujours vers `NullSender`, quel que soit
    `transport` — le dry-run ne valide que l'encodage, pas le transport.
    `compress` s'applique quel que soit le transport choisi (y compris
    `NullSender`, pour pouvoir valider l'encodage compressé en dry-run).
    `retries`/`retry_backoff` ne s'appliquent qu'aux senders réseau
    (`UDPSender`/`TCPSender`) : `NullSender` ne peut pas échouer, un retry
    n'y aurait aucun sens.
    """
    if dry_run:
        return NullSender(compress=compress)
    if transport == "udp":
        return UDPSender(
            host, port, compress=compress, retries=retries, retry_backoff=retry_backoff
        )
    if transport in ("tcp", "tls"):
        return TCPSender(
            host,
            port,
            tls=(transport == "tls"),
            tls_verify=tls_verify,
            tls_ca_file=tls_ca_file,
            compress=compress,
            retries=retries,
            retry_backoff=retry_backoff,
        )
    raise ValueError(
        _("transport HEP inconnu : {transport!r} (attendu : {expected})").format(
            transport=transport, expected=", ".join(TRANSPORTS)
        )
    )


# Re-exporté pour faciliter le typing dans les tests
SenderFactory = Callable[[HepPacket], None]
