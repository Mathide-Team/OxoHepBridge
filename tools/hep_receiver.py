#!/usr/bin/env python3
"""Harnais de réception HEPv3 standalone.

Écoute sur un port UDP, décode chaque paquet HEPv3 reçu avec la même fonction
``decode()`` que l'encodeur, et affiche un résumé JSONL (un objet par paquet)
sur la sortie standard.

Usage typique (pour valider l'envoi de oxo-hep-bridge sans instance HOMER réelle) :

    # terminal 1 — récepteur de test
    python -m tools.hep_receiver --port 9060

    # terminal 2 — le pont en dry-run ou vers ce récepteur
    oxo-hep-bridge --pcap sample_captures/ua3g_freeseating_ipv4.pcap \\
        --hep-host 127.0.0.1 --hep-port 9060

Chaque paquet décodé produit une ligne JSON du type :

    {"chunks":13,"src":"172.19.104.10:32640","dst":"172.19.31.87:32512",
     "fields":{"ip_protocol_family":"IPv4","protocol_type":100,
     "capture_agent_id":2001,"correlation_id":"172.19.104.10:32640-...",
     "node_name":"oxo-test-01","payload":"{\\"uaudp\\":{...}}"},
     "payload_bytes":311,"payload_preview":"...","from":"127.0.0.1:50773"}

Valide ainsi, de bout en bout, que les paquets HEP produits par le pont sont
décodables par un récepteur conforme à la spec (round-trip encode → réseau →
decode indépendant).
"""

from __future__ import annotations

import argparse
import gzip
import json
import socket
import sys

from loguru import logger

from oxo_hep_bridge.hep import (
    ChunkType,
    decode,
)

# Map inverse des types de chunks vers un nom lisible (pour le résumé JSONL)
_CHUNK_NAMES = {
    getattr(ChunkType, name): name.lower() for name in dir(ChunkType) if not name.startswith("_")
}

# Types de chunks contenant une adresse IP, selon le family lu dans le chunk
# IP_PROTOCOL_FAMILY (2=IPv4, 10=IPv6). La taille du payload (4 ou 16 octets)
# détermine aussi le format.
_IP_CHUNK_TYPES = {
    ChunkType.IPV4_SRC,
    ChunkType.IPV4_DST,
    ChunkType.IPV6_SRC,
    ChunkType.IPV6_DST,
}

# Types de chunks contenant un entier big-endian
_INT_CHUNK_TYPES = {
    ChunkType.SRC_PORT,
    ChunkType.DST_PORT,
    ChunkType.KEEPALIVE_TIMER,
    ChunkType.TIMESTAMP_SEC,
    ChunkType.TIMESTAMP_USEC,
    ChunkType.CAPTURE_AGENT_ID,
}


def _decode_value(chunk_type: int, payload: bytes) -> object:  # noqa: PLR0911
    """Décode grossièrement la valeur d'un chunk pour le résumé JSONL.

    Les octet-string (auth_key, node_name, correlation_id, payload) sont
    retournés comme chaîne décodée en UTF-8 (avec fallback hex) ; les
    entiers sont interprétés selon le type de chunk.
    """
    logger.trace("_decode_value() appelée | chunk={:#06x}", chunk_type)
    if not payload:
        logger.trace("_decode_value() retourne | vide")
        return ""
    if chunk_type == ChunkType.IP_PROTOCOL_FAMILY:
        logger.trace("_decode_value() retourne | famille IP")
        return {2: "IPv4", 10: "IPv6"}.get(payload[0], payload[0])
    if chunk_type == ChunkType.IP_PROTOCOL_ID:
        logger.trace("_decode_value() retourne | protocole IP")
        return {6: "TCP", 17: "UDP"}.get(payload[0], payload[0])
    if chunk_type == ChunkType.PROTOCOL_TYPE:
        logger.trace("_decode_value() retourne | proto_type")
        return payload[0]
    if chunk_type in _IP_CHUNK_TYPES:
        # Le format (IPv4 vs IPv6) est déduit de la taille du payload : 4 octets
        # pour une adresse IPv4, 16 pour une adresse IPv6.
        family = socket.AF_INET6 if len(payload) == 16 else socket.AF_INET
        try:
            adresse = socket.inet_ntop(family, payload)
        except (ValueError, OSError) as exc:
            logger.trace("_decode_value() retourne | hex (adresse invalide : {})", exc)
            return payload.hex()
        else:
            logger.trace("_decode_value() retourne | adresse IP")
            return adresse
    if chunk_type in _INT_CHUNK_TYPES:
        logger.trace("_decode_value() retourne | entier")
        return int.from_bytes(payload, "big")
    try:
        texte = payload.decode("utf-8")
    except UnicodeDecodeError:
        logger.trace("_decode_value() retourne | hex (non UTF-8)")
        return payload.hex()
    else:
        logger.trace("_decode_value() retourne | chaîne")
        return texte


def _decompress_payload(payload: bytes) -> str:
    """Décompresse un chunk COMPRESSED_PAYLOAD (gzip) en texte UTF-8.

    Retombe sur une représentation hex si la décompression ou le décodage
    UTF-8 échoue (paquet corrompu/tronqué), plutôt que de lever et
    interrompre la réception des paquets suivants — cohérent avec le
    fallback hex déjà utilisé par `_decode_value()` pour les octet-string
    non-UTF-8.
    """
    logger.trace("_decompress_payload() appelée | {} octet(s)", len(payload))
    try:
        raw = gzip.decompress(payload)
    except OSError as exc:
        logger.trace("_decompress_payload() retourne | hex (gzip invalide : {})", exc)
        return f"<gzip invalide ({len(payload)} octets bruts) : {payload.hex()}>"
    try:
        texte = raw.decode("utf-8")
    except UnicodeDecodeError:
        logger.trace("_decompress_payload() retourne | hex (non UTF-8)")
        return raw.hex()
    else:
        logger.trace("_decompress_payload() retourne | texte décompressé")
        return texte


def summarize_packet(raw: bytes) -> dict:
    """Produit un résumé lisible d'un paquet HEPv3 brut."""
    logger.trace("summarize_packet() appelée | {} octet(s)", len(raw))
    chunks = decode(raw)
    summary: dict[str, object] = {"chunks": len(chunks)}
    decoded_fields: dict[str, object] = {}

    src_port = dst_port = 0
    src_ip = dst_ip = ""
    for _vendor, chunk_type, payload in chunks:
        name = _CHUNK_NAMES.get(chunk_type, f"chunk_{chunk_type:#06x}")
        if chunk_type in _IP_CHUNK_TYPES:
            value = _decode_value(chunk_type, payload)
            if not isinstance(value, str):
                value = str(value)
            if chunk_type in (ChunkType.IPV4_SRC, ChunkType.IPV6_SRC):
                src_ip = value
            else:
                dst_ip = value
            decoded_fields[name] = value
        elif chunk_type == ChunkType.SRC_PORT:
            src_port = int.from_bytes(payload, "big")
            decoded_fields[name] = src_port
        elif chunk_type == ChunkType.DST_PORT:
            dst_port = int.from_bytes(payload, "big")
            decoded_fields[name] = dst_port
        elif chunk_type == ChunkType.COMPRESSED_PAYLOAD:
            # Rangé sous la même clé "payload" qu'un chunk PAYLOAD en clair —
            # les deux sont mutuellement exclusifs à l'encodage (hep.py) et
            # le résumé JSONL ne doit pas distinguer la présentation selon le
            # chunk source, seulement signaler la compression à part.
            decoded_fields["payload"] = _decompress_payload(payload)
            decoded_fields["payload_compressed"] = True
            decoded_fields["payload_wire_bytes"] = len(payload)
        else:
            decoded_fields[name] = _decode_value(chunk_type, payload)

    summary["src"] = f"{src_ip}:{src_port}"
    summary["dst"] = f"{dst_ip}:{dst_port}"
    summary["fields"] = decoded_fields
    # aperçu de la payload (limité pour la lisibilité du JSONL)
    payload_data = decoded_fields.get("payload")
    if isinstance(payload_data, str):
        summary["payload_bytes"] = len(payload_data.encode("utf-8"))
        summary["payload_preview"] = payload_data[:120]
    logger.trace("summarize_packet() retourne | résumé construit")
    return summary


def main(argv: list[str] | None = None) -> int:
    logger.debug("main() appelée | argv={}", argv)
    parser = argparse.ArgumentParser(
        prog="hep_receiver",
        description="Récepteur HEPv3 de test pour oxo-hep-bridge (valide l'encodage par round-trip)",
    )
    parser.add_argument("--host", default="0.0.0.0", help="Adresse d'écoute")  # noqa: S104
    parser.add_argument("--port", type=int, default=9060, help="Port UDP d'écoute")
    parser.add_argument(
        "--max",
        type=int,
        default=None,
        help="Nombre de paquets à recevoir avant de s'arrêter (défaut: illimité)",
    )
    parser.add_argument(
        "--summary-only",
        action="store_true",
        help="N'affiche qu'un résumé compact par paquet (sans les champs détaillés)",
    )
    args = parser.parse_args(argv)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((args.host, args.port))
    print(
        f"Récepteur HEPv3 en écoute sur {args.host}:{args.port} (Ctrl-C pour arrêter)",
        file=sys.stderr,
        flush=True,
    )

    received = 0
    try:
        while args.max is None or received < args.max:
            data, addr = sock.recvfrom(65535)
            try:
                summary = summarize_packet(data)
            except ValueError as exc:
                logger.debug("main() : paquet invalide ignoré : {}", exc)
                print(
                    json.dumps(
                        {"error": str(exc), "from": f"{addr[0]}:{addr[1]}", "raw_len": len(data)}
                    ),
                    flush=True,
                )
                continue
            summary["from"] = f"{addr[0]}:{addr[1]}"
            if args.summary_only:
                print(
                    json.dumps(
                        {
                            "from": summary["from"],
                            "src": summary.get("src"),
                            "dst": summary.get("dst"),
                            "chunks": summary.get("chunks"),
                        }
                    ),
                    flush=True,
                )
            else:
                print(json.dumps(summary, ensure_ascii=False), flush=True)
            received += 1
    except KeyboardInterrupt as exc:
        logger.debug("main() : arrêt demandé ({} paquet(s) reçus) : {}", received, exc)
        print(f"\nArrêt. {received} paquet(s) reçu(s).", file=sys.stderr, flush=True)
    finally:
        sock.close()
    logger.debug("main() retourne | 0 (récepteur arrêté)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
