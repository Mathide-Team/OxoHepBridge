#!/usr/bin/env python3
"""Encodeur/décodeur HEPv3 (Homer Encapsulation Protocol v3) — implémentation pure
Python, sans dépendance externe.

Spécification : draft-dubovikov-eep-hep-00 / HEP3 rev12
  - https://www.voztovoice.org/sites/default/files/hep3_rev12.pdf
Référence d'implémentation : heplify-server decoder/decoder.go

Format paquet HEPv3 :
  "HEP3" (4 octets ASCII) + longueur totale (uint16 BE) + chunks
Format chunk :
  vendor_id (uint16) + chunk_type (uint16) + chunk_length (uint16, inclut l'en-tête
  de 6 octets) + payload
"""

from __future__ import annotations

import gzip
import ipaddress
import struct
from dataclasses import dataclass
from typing import ClassVar

from oxo_hep_bridge.i18n import _

HEP3_MAGIC = b"HEP3"
CHUNK_HEADER_FMT = struct.Struct(">HHH")  # vendor_id, chunk_type, chunk_length
PACKET_HEADER_FMT = struct.Struct(">4sH")  # magic, total_length
CHUNK_HEADER_SIZE = 6
PACKET_HEADER_SIZE = 6  # "HEP3"(4) + total_length(2)


# --- Types de chunks génériques (vendor_id 0x0000) ---
# Source : HEP3 rev12 + heplify-server decoder.go
class ChunkType:
    IP_PROTOCOL_FAMILY = 0x0001  # uint8  (2=IPv4, 10=IPv6)
    IP_PROTOCOL_ID = 0x0002  # uint8  (6=TCP, 17=UDP)
    IPV4_SRC = 0x0003  # inet4-addr
    IPV4_DST = 0x0004  # inet4-addr
    IPV6_SRC = 0x0005  # inet6-addr
    IPV6_DST = 0x0006  # inet6-addr
    SRC_PORT = 0x0007  # uint16
    DST_PORT = 0x0008  # uint16
    TIMESTAMP_SEC = 0x0009  # uint32 (epoch)
    TIMESTAMP_USEC = 0x000A  # uint32 (microsecondes, ajoutées au timestamp)
    PROTOCOL_TYPE = 0x000B  # uint8 (SIP/RTP/RTCP/LOG...)
    CAPTURE_AGENT_ID = 0x000C  # uint32
    KEEPALIVE_TIMER = 0x000D  # uint16
    AUTH_KEY = 0x000E  # octet-string
    PAYLOAD = 0x000F  # octet-string (payload capturé)
    COMPRESSED_PAYLOAD = 0x0010  # octet-string (gzip/inflate)
    CORRELATION_ID = 0x0011  # octet-string (internal correlation id)
    VLAN_ID = 0x0012  # uint8
    NODE_NAME = 0x0013  # octet-string (group id / node name)


class VendorID:
    GENERIC = 0x0000


# --- Valeurs de protocol type (chunk 0x000B) ---
class ProtoType:
    SIP = 0x01
    H323 = 0x02
    SDP = 0x03
    RTP = 0x04
    RTCP = 0x05
    MGCP = 0x06
    MEGACO = 0x07
    M2UA = 0x08
    M3UA = 0x09
    IAX = 0x10
    LOG = 0x64  # 100 — log générique, recommandé pour UA custom non-SIP


# --- IP protocol family (chunk 0x0001) ---
IPV4 = 0x02
IPV6 = 0x0A

# --- IP protocol ID (chunk 0x0002) ---
PROTO_UDP = 0x11
PROTO_TCP = 0x06


@dataclass
class HepPacket:
    """Représentation logique d'un paquet HEPv3, avant encodage binaire."""

    ip_family: int = IPV4
    ip_proto: int = PROTO_UDP
    src_ip: str = "0.0.0.0"  # noqa: S104 -- valeur neutre par défaut, pas une adresse d'écoute
    dst_ip: str = "0.0.0.0"  # noqa: S104 -- idem
    src_port: int = 0
    dst_port: int = 0
    timestamp_sec: int = 0
    timestamp_usec: int = 0
    proto_type: int = ProtoType.LOG
    capture_agent_id: int = 0
    payload: bytes = b""
    auth_key: str | None = None
    correlation_id: str | None = None
    node_name: str | None = None
    keepalive_timer: int | float | None = None

    # Ordre canonique des 10 chunks obligatoires à l'encodage — vérifié
    # explicitement contre la sortie réelle de encode() par
    # test_field_chunks_matches_actual_encode_order (tests/test_hep.py).
    # Jusqu'à la session 28, cette déclaration n'était référencée nulle part
    # ailleurs dans le projet (ni par encode(), qui construit la même
    # séquence indépendamment à la main, ni par aucun test) : la promesse
    # « reproductible pour les tests » n'était vérifiée par rien. Trouvé en
    # cherchant `_FIELD_CHUNKS` dans tout le dépôt (même démarche que pour
    # les autres constantes « source de vérité » du projet, ex: `_CAPTURE_KEYS`
    # dans tests/test_docs.py).
    _FIELD_CHUNKS: ClassVar[tuple[str, ...]] = (
        "ip_protocol_family",
        "ip_protocol_id",
        "src_ip",
        "dst_ip",
        "src_port",
        "dst_port",
        "timestamp_sec",
        "timestamp_usec",
        "protocol_type",
        "capture_agent_id",
    )


def _encode_uint8(v: int) -> bytes:
    return struct.pack(">B", int(v) & 0xFF)


def _encode_uint16(v: int | float) -> bytes:
    return struct.pack(">H", int(v) & 0xFFFF)


def _encode_uint32(v: int) -> bytes:
    return struct.pack(">I", int(v) & 0xFFFFFFFF)


def _encode_octet_string(v: bytes | str) -> bytes:
    return v.encode("utf-8") if isinstance(v, str) else bytes(v)


def _encode_inet(ip: str, family: int) -> bytes:
    addr = ipaddress.ip_address(ip)
    if isinstance(addr, ipaddress.IPv6Address) and family != IPV6:
        raise ValueError(_("IPv6 fournie mais ip_family={family}").format(family=family))
    if isinstance(addr, ipaddress.IPv4Address) and family != IPV4:
        raise ValueError(_("IPv4 fournie mais ip_family={family}").format(family=family))
    return addr.packed


def _chunk(vendor: int, chunk_type: int, payload: bytes) -> bytes:
    """Construit un chunk : vendor(2) + type(2) + length(2, inclut 6 octets) + payload."""
    return CHUNK_HEADER_FMT.pack(vendor, chunk_type, CHUNK_HEADER_SIZE + len(payload)) + payload


def encode(pkt: HepPacket, *, compress: bool = False) -> bytes:
    """Encode un HepPacket en bytes HEPv3 valides.

    `compress=True` remplace le chunk PAYLOAD (0x000F) par le chunk
    COMPRESSED_PAYLOAD (0x0010, gzip) : `pkt.payload` est compressé via
    `gzip.compress()` avant d'être écrit, les deux chunks sont mutuellement
    exclusifs (jamais émis ensemble — c'est le chunk présent, 0x000F ou
    0x0010, qui indique au collecteur comment lire le payload, pas un champ
    séparé). Utile sur des liens contraints ou pour réduire la charge sur le
    collecteur lors de pics de trafic ; le gain dépend du contenu (le
    payload JSON structuré de `semantics.py` compresse bien, les clés/valeurs
    répétitives d'un paquet à l'autre).
    """
    chunks: list[bytes] = []

    # IP family
    chunks.append(
        _chunk(VendorID.GENERIC, ChunkType.IP_PROTOCOL_FAMILY, _encode_uint8(pkt.ip_family))
    )
    # IP proto
    chunks.append(_chunk(VendorID.GENERIC, ChunkType.IP_PROTOCOL_ID, _encode_uint8(pkt.ip_proto)))
    # src/dst IP
    ip_src_chunk = ChunkType.IPV4_SRC if pkt.ip_family == IPV4 else ChunkType.IPV6_SRC
    ip_dst_chunk = ChunkType.IPV4_DST if pkt.ip_family == IPV4 else ChunkType.IPV6_DST
    chunks.append(_chunk(VendorID.GENERIC, ip_src_chunk, _encode_inet(pkt.src_ip, pkt.ip_family)))
    chunks.append(_chunk(VendorID.GENERIC, ip_dst_chunk, _encode_inet(pkt.dst_ip, pkt.ip_family)))
    # ports
    chunks.append(_chunk(VendorID.GENERIC, ChunkType.SRC_PORT, _encode_uint16(pkt.src_port)))
    chunks.append(_chunk(VendorID.GENERIC, ChunkType.DST_PORT, _encode_uint16(pkt.dst_port)))
    # timestamps
    chunks.append(
        _chunk(VendorID.GENERIC, ChunkType.TIMESTAMP_SEC, _encode_uint32(pkt.timestamp_sec))
    )
    chunks.append(
        _chunk(VendorID.GENERIC, ChunkType.TIMESTAMP_USEC, _encode_uint32(pkt.timestamp_usec))
    )
    # proto type
    chunks.append(_chunk(VendorID.GENERIC, ChunkType.PROTOCOL_TYPE, _encode_uint8(pkt.proto_type)))
    # capture agent id
    chunks.append(
        _chunk(VendorID.GENERIC, ChunkType.CAPTURE_AGENT_ID, _encode_uint32(pkt.capture_agent_id))
    )
    # auth key (optionnel)
    if pkt.auth_key:
        chunks.append(
            _chunk(VendorID.GENERIC, ChunkType.AUTH_KEY, _encode_octet_string(pkt.auth_key))
        )
    # correlation id (optionnel)
    if pkt.correlation_id:
        chunks.append(
            _chunk(
                VendorID.GENERIC, ChunkType.CORRELATION_ID, _encode_octet_string(pkt.correlation_id)
            )
        )
    # node name (optionnel) — group id / node name du collecteur HEP
    if pkt.node_name:
        chunks.append(
            _chunk(VendorID.GENERIC, ChunkType.NODE_NAME, _encode_octet_string(pkt.node_name))
        )
    # keepalive timer (optionnel) — indique au collecteur l'intervalle (en
    # secondes) auquel s'attendre à recevoir des paquets de cet agent
    if pkt.keepalive_timer is not None:
        chunks.append(
            _chunk(
                VendorID.GENERIC,
                ChunkType.KEEPALIVE_TIMER,
                _encode_uint16(pkt.keepalive_timer),
            )
        )
    # payload — en clair (0x000F) ou compressé gzip (0x0010), jamais les deux
    if compress:
        compressed = gzip.compress(_encode_octet_string(pkt.payload))
        chunks.append(_chunk(VendorID.GENERIC, ChunkType.COMPRESSED_PAYLOAD, compressed))
    else:
        chunks.append(
            _chunk(VendorID.GENERIC, ChunkType.PAYLOAD, _encode_octet_string(pkt.payload))
        )

    body = b"".join(chunks)
    total_len = PACKET_HEADER_SIZE + len(body)
    return PACKET_HEADER_FMT.pack(HEP3_MAGIC, total_len) + body


def decode(packet: bytes) -> list[tuple[int, int, bytes]]:
    """Décode un paquet HEPv3 et renvoie [(vendor_id, chunk_type, payload), ...].

    Utilisé pour les tests de round-trip. Valide magic + longueur totale.
    """
    if len(packet) < PACKET_HEADER_SIZE:
        raise ValueError(_("Paquet trop court pour un en-tête HEPv3"))
    magic, total_len = PACKET_HEADER_FMT.unpack(packet[:PACKET_HEADER_SIZE])
    if magic != HEP3_MAGIC:
        raise ValueError(_("Magic HEP3 attendu, reçu {magic!r}").format(magic=magic))
    if total_len != len(packet):
        raise ValueError(
            _("Longueur totale annoncée {announced} ≠ {actual}").format(
                announced=total_len, actual=len(packet)
            )
        )

    chunks: list[tuple[int, int, bytes]] = []
    offset = PACKET_HEADER_SIZE
    while offset < total_len:
        if offset + CHUNK_HEADER_SIZE > total_len:
            raise ValueError(_("En-tête de chunk tronqué"))
        vendor, chunk_type, chunk_len = CHUNK_HEADER_FMT.unpack(
            packet[offset : offset + CHUNK_HEADER_SIZE]
        )
        if chunk_len < CHUNK_HEADER_SIZE or offset + chunk_len > total_len:
            raise ValueError(_("Longueur de chunk invalide : {length}").format(length=chunk_len))
        payload = packet[offset + CHUNK_HEADER_SIZE : offset + chunk_len]
        chunks.append((vendor, chunk_type, payload))
        offset += chunk_len
    return chunks
