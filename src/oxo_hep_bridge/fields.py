#!/usr/bin/env python3
"""Fonctions utilitaires partagées pour l'extraction de champs depuis les
paquets tshark -T ek aplatis (flat dict). Utilisées à la fois par
``normalizer.py`` et ``semantics.py``.
"""

from __future__ import annotations

from typing import Any

from loguru import logger


def pick(value: Any, index: int = 0) -> Any:
    """Retourne value[index] si value est une liste, sinon value tel quel.

    tshark -T ek encode parfois un champ répété (ex: udp.port apparaissant
    deux fois) comme une liste plutôt qu'un scalaire.
    """
    logger.trace("pick() appelée")
    if isinstance(value, list):
        resultat = value[index] if len(value) > index else None
        logger.trace("pick() retourne | élément de liste")
        return resultat
    logger.trace("pick() retourne | valeur scalaire")
    return value


def as_int(value: Any, default: int = 0) -> int:
    logger.trace("as_int() appelée")
    v = pick(value)
    if v is None:
        logger.trace("as_int() retourne | défaut (valeur absente)")
        return default
    try:
        nombre = int(v)
    except (TypeError, ValueError) as exc:
        logger.trace("as_int() retourne | défaut (non convertible : {})", exc)
        return default
    else:
        logger.trace("as_int() retourne | entier")
        return nombre


def as_str(value: Any, default: str = "") -> str:
    logger.trace("as_str() appelée")
    v = pick(value)
    texte = default if v is None else str(v)
    logger.trace("as_str() retourne | chaîne")
    return texte


def extract_noe_events(flat: dict[str, Any]) -> list[dict[str, Any]]:
    """Extrait les événements NOE d'un paquet aplati.

    Le champ "noe" peut être un objet unique OU une liste d'objets quand
    plusieurs messages NOE sont empilés dans un seul paquet UA3G. Présent
    dans les captures d'exemple ``ua3g_freeseating_*`` (chaîne de
    dissection complète ``eth:ip:udp:uaudp:ua:noe``, voir
    tests/test_fields.py::test_extract_noe_events_finds_real_events_in_ua3g_freeseating_fixture),
    absent de ``uaudp_ipv6`` (tshark s'arrête à la couche ``uaudp``, voir
    docs/architecture.md#limites-connues).
    """
    logger.trace("extract_noe_events() appelée")
    noe = flat.get("noe")
    if noe is None:
        logger.trace("extract_noe_events() retourne | aucun événement")
        return []
    if isinstance(noe, list):
        evenements = [n for n in noe if isinstance(n, dict)]
        logger.trace("extract_noe_events() retourne | {} événement(s) (liste)", len(evenements))
        return evenements
    if isinstance(noe, dict):
        logger.trace("extract_noe_events() retourne | 1 événement (objet)")
        return [noe]
    logger.trace("extract_noe_events() retourne | aucun événement (type inattendu)")
    return []


def extract_noe_events_flat(flat: dict[str, Any]) -> list[dict[str, Any]]:
    """Comme extract_noe_events, mais retire le préfixe "noe_noe_" des clés
    de chaque événement pour produire des noms de champs propres.
    """
    logger.trace("extract_noe_events_flat() appelée")
    events = extract_noe_events(flat)
    aplaties = [
        {k[len("noe_noe_") :] if k.startswith("noe_noe_") else k: v for k, v in ev.items()}
        for ev in events
    ]
    logger.trace("extract_noe_events_flat() retourne | {} événement(s)", len(aplaties))
    return aplaties


def build_correlation_id(flat: dict[str, Any]) -> str:
    """Construit un identifiant de corrélation UA stable pour une session.

    Faute d'un identifiant de session natif exposé par le dissecteur UAUDP,
    on synthétise une clé à partir des adresses/ports IP. Les endpoints sont
    **canonicalisés** (triés) pour que A→B et B→A produisent le même
    identifiant de flux — indispensable pour corréler les deux sens d'une
    même conversation UDP dans HOMER. Cette heuristique doit être affinée si un
    identifiant plus stable est disponible côté OXO (ex: un identifiant de
    poste/appel, ou le champ ``transaction_id`` si le dissecteur l'expose).
    """
    logger.trace("build_correlation_id() appelée")
    src_ip = as_str(flat.get("ip_ip_src") or flat.get("ipv6_ipv6_src"))
    dst_ip = as_str(flat.get("ip_ip_dst") or flat.get("ipv6_ipv6_dst"))
    src_port = as_int(flat.get("udp_udp_srcport"))
    dst_port = as_int(flat.get("udp_udp_dstport"))
    endpoint_a = (src_ip, src_port)
    endpoint_b = (dst_ip, dst_port)
    lo, hi = sorted((endpoint_a, endpoint_b))
    identifiant = f"{lo[0]}:{lo[1]}-{hi[0]}:{hi[1]}"
    logger.trace("build_correlation_id() retourne | identifiant de flux")
    return identifiant
