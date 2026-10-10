#!/usr/bin/env python3
"""Bridge : orchestre source (tshark -T ek) -> normaliseur -> encodeur HEP -> sender."""

from __future__ import annotations

import time
from collections.abc import Iterator
from dataclasses import replace

from loguru import logger

from oxo_hep_bridge.config import Config
from oxo_hep_bridge.hep import HepPacket
from oxo_hep_bridge.i18n import _
from oxo_hep_bridge.keepalive import KeepaliveScheduler
from oxo_hep_bridge.normalizer import normalize
from oxo_hep_bridge.sender import make_sender
from oxo_hep_bridge.stats import Stats
from oxo_hep_bridge.tshark_source import TsharkEKSource, TsharkError


class Bridge:
    def __init__(self, config: Config) -> None:
        self.config = config
        self.source = TsharkEKSource(
            tshark_path=config.capture.tshark_path,
            interface=config.capture.interface,
            pcap=config.capture.pcap,
            bpf=config.capture.bpf,
            fields=config.capture.fields,
            decode_as=config.capture.decode_as,
        )
        self.sender = make_sender(
            host=config.hep.host,
            port=config.hep.port,
            dry_run=config.dry_run,
            transport=config.hep.transport,
            tls_verify=config.hep.tls_verify,
            tls_ca_file=config.hep.tls_ca_file,
            compress=config.hep.compress_payload,
            retries=config.hep.send_retries,
            retry_backoff=config.hep.send_retry_backoff,
        )
        self.keepalive = KeepaliveScheduler(
            sender=self.sender,
            interval=config.hep.keepalive_interval,
            capture_agent_id=config.hep.capture_agent_id,
            proto_type=config.hep.proto_type,
            auth_key=config.hep.auth_key,
            node_name=config.hep.node_name,
        )

        # Décalage (µs) appliqué aux horodatages en relecture --pcap-retime,
        # fixé au premier paquet normalisé (voir retime()).
        self._retime_offset_us: int | None = None

    def retime(self, packet: HepPacket) -> HepPacket:
        """--pcap-retime : premier paquet = maintenant, écarts relatifs conservés."""
        if not (self.config.capture.pcap and self.config.capture.pcap_retime):
            return packet
        original_us = packet.timestamp_sec * 1_000_000 + packet.timestamp_usec
        if self._retime_offset_us is None:
            self._retime_offset_us = time.time_ns() // 1000 - original_us
            logger.debug("pcap-retime : décalage de {} s", self._retime_offset_us // 1_000_000)
        shifted_us = original_us + self._retime_offset_us
        return replace(
            packet, timestamp_sec=shifted_us // 1_000_000, timestamp_usec=shifted_us % 1_000_000
        )

    def normalize_packet(self, flat: dict) -> HepPacket | None:
        packet = normalize(
            flat,
            capture_agent_id=self.config.hep.capture_agent_id,
            proto_type=self.config.hep.proto_type,
            correlation_field=self.config.normalizer.correlation_field,
            auth_key=self.config.hep.auth_key,
            node_name=self.config.hep.node_name,
        )
        return None if packet is None else self.retime(packet)

    def run(self) -> int:
        self.stats = Stats()
        stats = self.stats
        # Le keepalive n'a de sens qu'en capture live : une relecture pcap se
        # termine d'elle-même en quelques secondes, bien avant tout intervalle
        # de keepalive raisonnable.
        keepalive_active = self.keepalive.enabled and not self.config.capture.pcap
        if keepalive_active:
            self.keepalive.start()
        try:
            for flat in self.source.iter_packets():
                stats.received += 1
                try:
                    packet = self.normalize_packet(flat)
                except Exception:
                    logger.exception(
                        _("erreur inattendue pendant normalize() sur le paquet #{}"), stats.received
                    )
                    stats.normalize_errors += 1
                    continue
                if packet is None:
                    stats.skipped += 1
                    continue
                stats.normalized += 1
                if self.sender.send(packet):
                    stats.sent += 1
                else:
                    stats.send_errors += 1
                interval = self.config.logging.stats_interval
                if interval > 0 and stats.sent % interval == 0 and stats.sent > 0:
                    # logger.bind() lie le dict complet de Stats.to_dict() à cet
                    # enregistrement — invisible en sortie texte humaine (stderr),
                    # exploité par un éventuel sink JSON (--log-json-file, voir
                    # cli.py), comme pour Stats.log_summary() (stats.py).
                    logger.bind(stats=stats.to_dict()).info(
                        "progression : {} paquets envoyés ({} ignorés, {} erreurs)",
                        stats.sent,
                        stats.skipped,
                        stats.send_errors,
                    )
        except TsharkError as exc:
            stats.tshark_errors += 1
            logger.error(_("tshark a signalé une erreur fatale : {}"), exc)
            # retry_count vaut 0 par défaut sur la classe de base Sender
            # (NullSender et les senders factices de test ne peuvent pas
            # échouer) ; UDPSender et TCPSender l'incrémentent à chaque
            # nouvelle tentative consommée par --hep-retries.
            stats.send_retries = self.sender.retry_count
            stats.log_summary(verbose=True)
            return 1
        finally:
            if keepalive_active:
                self.keepalive.stop()
            # close() est un no-op par défaut sur la classe de base Sender
            # (NullSender n'a pas de socket à fermer) ; UDPSender et
            # TCPSender la surchargent pour fermer proprement leur socket.
            self.sender.close()
        stats.send_retries = self.sender.retry_count
        stats.log_summary()
        return 0

    def iter_normalized(self) -> Iterator[HepPacket]:
        """Itérateur utile pour les tests : yield les paquets normalisés sans envoyer."""
        for flat in self.source.iter_packets():
            packet = self.normalize_packet(flat)
            if packet is not None:
                yield packet
