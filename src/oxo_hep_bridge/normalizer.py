#!/usr/bin/env python3
"""Normalisation des champs UAUDP/UA3G/NOE décodés (via tshark -T ek) vers un
HepPacket prêt à encoder.

Les fonctions utilitaires d'extraction de champs (`pick`, `as_int`, `as_str`,
`extract_noe_events`, `build_correlation_id`) vivent dans ``oxo_hep_bridge.fields``
et sont réexportées ici pour préserver la compatibilité descendante des
importations depuis ``oxo_hep_bridge.normalizer``.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from loguru import logger

from oxo_hep_bridge.fields import (
    as_int,
    as_str,
    build_correlation_id,
    extract_noe_events,
    pick,
)
from oxo_hep_bridge.hep import IPV4, IPV6, PROTO_TCP, PROTO_UDP, HepPacket, ProtoType
from oxo_hep_bridge.i18n import _
from oxo_hep_bridge.semantics import encode_semantic_payload

__all__ = [
    "as_int",
    "as_str",
    "build_correlation_id",
    "extract_noe_events",
    "normalize",
    "pick",
]


def normalize(
    flat: dict[str, Any],
    *,
    capture_agent_id: int,
    proto_type: int = ProtoType.LOG,
    correlation_field: str = "",
    auth_key: str | None = None,
    node_name: str | None = None,
) -> HepPacket | None:
    """Transforme un paquet aplati (issu de tshark_source.flatten_layers) en
    HepPacket. Retourne None si le paquet ne contient aucune donnée UA
    exploitable (ex: bruit DHCP/TFTP capturé par erreur sur le même port).

    La payload HEP est produite par ``semantics.encode_semantic_payload`` :
    un JSON structuré (uaudp, endpoints, qos, correlation_id, raw_selected)
    plutôt qu'un déversement brut des champs tshark.
    """
    payload = encode_semantic_payload(flat)
    if payload is None:
        return None

    ip_family = IPV6 if "ipv6_ipv6_src" in flat else IPV4
    src_ip = as_str(flat.get("ipv6_ipv6_src") or flat.get("ip_ip_src"), "0.0.0.0")  # noqa: S104
    dst_ip = as_str(flat.get("ipv6_ipv6_dst") or flat.get("ip_ip_dst"), "0.0.0.0")  # noqa: S104

    ip_proto = PROTO_TCP if "tcp_tcp_srcport" in flat else PROTO_UDP

    frame_time_epoch = flat.get("frame_frame_time_epoch")
    ts_sec, ts_usec = _split_epoch(as_str(frame_time_epoch))

    correlation_id = as_str(flat.get(correlation_field)) if correlation_field else ""
    if not correlation_id:
        correlation_id = build_correlation_id(flat)

    return HepPacket(
        ip_family=ip_family,
        ip_proto=ip_proto,
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=as_int(flat.get("udp_udp_srcport") or flat.get("tcp_tcp_srcport")),
        dst_port=as_int(flat.get("udp_udp_dstport") or flat.get("tcp_tcp_dstport")),
        timestamp_sec=ts_sec,
        timestamp_usec=ts_usec,
        proto_type=proto_type,
        capture_agent_id=capture_agent_id,
        payload=payload,
        correlation_id=correlation_id,
        auth_key=auth_key,
        node_name=node_name,
    )


def _split_epoch(epoch_str: str) -> tuple[int, int]:
    """Découpe un timestamp ISO8601 tshark ('2018-04-09T15:14:54.770911000Z')
    en (secondes epoch, microsecondes). Retombe sur l'heure courante si
    absent/invalide plutôt que d'échouer.

    tshark fournit des nanosecondes (9 chiffres de fraction) ; on tronque à
    6 chiffres (microsecondes) avant de parser, car datetime.fromisoformat
    n'accepte que jusqu'à 6 chiffres de fraction de seconde.
    """
    try:
        s = epoch_str.strip()
        if len(s) > 27:
            # tronquer la fraction de seconde à 6 chiffres (microsecondes)
            s = s[:20] + s[20:26] + "Z" if s.endswith("Z") else s[:26]
        dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
    except (ValueError, TypeError):
        logger.warning(_("timestamp tshark invalide {!r}, fallback now"), epoch_str)
        dt = datetime.now(UTC)
    return int(dt.timestamp()), dt.microsecond
