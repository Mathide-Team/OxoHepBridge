#!/usr/bin/env python3
"""Keepalive HEP périodique.

Sur une capture live, du trafic OXO peut manquer pendant de longues périodes
(veille de nuit, PABX peu chargé) sans que cela signifie que le pont est en
panne. Sans signal de vie, un collecteur HOMER/heplify-server ne peut pas
distinguer « aucun trafic » de « agent mort ». On envoie donc périodiquement
un paquet HEPv3 minimal (chunk KEEPALIVE_TIMER 0x000D + payload JSON de
signalement) pour indiquer que l'agent est toujours actif.

Implémenté comme une boucle de fond sur un thread daemon, arrêtable proprement
via `threading.Event` (même style que le drain stderr de tshark_source.py).
N'est démarré par `Bridge` qu'en capture live (`--interface`) : en relecture
pcap (`--pcap`), le run se termine de lui-même et un keepalive n'aurait pas
de sens.
"""

from __future__ import annotations

import json
import threading
from datetime import UTC, datetime

from loguru import logger

from oxo_hep_bridge.hep import IPV4, HepPacket, ProtoType
from oxo_hep_bridge.i18n import _
from oxo_hep_bridge.sender import Sender


def build_keepalive_packet(
    *,
    capture_agent_id: int,
    interval: int | float,
    proto_type: int = ProtoType.LOG,
    auth_key: str | None = None,
    node_name: str | None = None,
) -> HepPacket:
    """Construit un HepPacket de signalement de vie (keepalive).

    Porte le chunk KEEPALIVE_TIMER (0x000D, l'intervalle en secondes) et une
    payload JSON minimale ``{"type": "keepalive", ...}`` facilement filtrable
    côté collecteur. Les adresses IP/ports sont neutres (0.0.0.0:0) puisque ce
    paquet ne représente aucun flux réseau réel.
    """
    now = datetime.now(UTC)
    payload = {
        "type": "keepalive",
        "node_name": node_name,
        "capture_agent_id": capture_agent_id,
        "interval_seconds": interval,
    }
    return HepPacket(
        ip_family=IPV4,
        src_ip="0.0.0.0",  # noqa: S104 -- neutre, voir docstring (aucun flux réel)
        dst_ip="0.0.0.0",  # noqa: S104 -- idem
        src_port=0,
        dst_port=0,
        timestamp_sec=int(now.timestamp()),
        timestamp_usec=now.microsecond,
        proto_type=proto_type,
        capture_agent_id=capture_agent_id,
        payload=json.dumps(payload, ensure_ascii=False).encode("utf-8"),
        auth_key=auth_key,
        node_name=node_name,
        keepalive_timer=interval,
    )


class KeepaliveScheduler:
    """Envoie un paquet HEP keepalive toutes les `interval` secondes sur un
    thread daemon, jusqu'à `stop()`.

    `interval <= 0` désactive le mécanisme : `start()` devient un no-op, ce
    qui évite à l'appelant (Bridge) de devoir tester la valeur avant d'appeler
    start/stop.
    """

    def __init__(
        self,
        *,
        sender: Sender,
        interval: int | float,
        capture_agent_id: int,
        proto_type: int = ProtoType.LOG,
        auth_key: str | None = None,
        node_name: str | None = None,
    ) -> None:
        self.sender = sender
        self.interval = interval
        self.capture_agent_id = capture_agent_id
        self.proto_type = proto_type
        self.auth_key = auth_key
        self.node_name = node_name
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None
        self.sent_count = 0

    @property
    def enabled(self) -> bool:
        return self.interval > 0

    def _build_packet(self) -> HepPacket:
        return build_keepalive_packet(
            capture_agent_id=self.capture_agent_id,
            interval=self.interval,
            proto_type=self.proto_type,
            auth_key=self.auth_key,
            node_name=self.node_name,
        )

    def _run(self) -> None:
        # Le premier keepalive est envoyé après un intervalle complet (pas au
        # démarrage) : le tout premier paquet réel du run fait déjà foi que
        # l'agent est vivant.
        while not self._stop_event.wait(self.interval):
            packet = self._build_packet()
            if self.sender.send(packet):
                self.sent_count += 1
                logger.debug(
                    "keepalive HEP envoyé (#{}, intervalle={}s)", self.sent_count, self.interval
                )
            else:
                logger.warning(_("échec d'envoi du keepalive HEP"))

    def start(self) -> None:
        if not self.enabled or self._thread is not None:
            return
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._run, name="oxo-hep-keepalive", daemon=True)
        self._thread.start()
        logger.debug("keepalive HEP démarré (intervalle={}s)", self.interval)

    def stop(self, *, timeout: float = 5.0) -> None:
        if self._thread is None:
            return
        self._stop_event.set()
        self._thread.join(timeout=timeout)
        self._thread = None
