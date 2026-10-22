#!/usr/bin/env python3
"""Extraction sémantique des champs UAUDP/UA3G observés dans les captures.

Contrairement à l'ancien déversement brut du contenu tshark aplati, ce module
produit une payload JSON structurée et stable, directement utilisable pour
le recherche/correlation dans HOMER.

Les noms métier "d'événement d'appel" (INVITE/BYE/...) ne sont PAS inventés
ici : on garde la valeur numérique dans ``opcode``/``class``/``method``/...
et on ne fait qu'isoler les familles de champs réellement présentes dans les
captures d'exemple Wireshark (ua3g_freeseating_*, uaudp_ipv6). Voir
docs/noe-ua3g-homer-mapping.md pour la synthèse expliquant pourquoi un
mapping opcode → événement d'appel SIP n'est pas codable en dur en l'état
(pas de trafic OXO réel pour corréler NOE ↔ Call-ID SIP par déduction).

En revanche, depuis cette session, les libellés **protocolaires officiels**
(ex: opcode UAUDP 7 → "Data", classe NOE 128 → "FrameBox") sont disponibles
et sourcés depuis le dissecteur Wireshark officiel Alcatel-Lucent Enterprise
(``packet-uaudp.c``/``packet-noe.c``, voir ``oxo_hep_bridge.ua_opcode_names``
et docs/noe-ua3g-homer-mapping.md §6bis). Ces libellés sont ajoutés en plus
des valeurs numériques (jamais à leur place) sous forme de champs ``*_name``
optionnels, uniquement quand une correspondance existe dans les tables — pas
de "unknown" inventé.

  - ``uaudp``        : opcode, sntseq, expseq (+ métriques QoS quand présentes)
                       — ``opcode_name`` ajouté si résolu (ex: "Data")
  - ``qos``          : window_size, mtu, udp_lost, udp_lost_reinit, keepalive,
                       superfast_connect, qos_ip_tos, version — uniquement sur
                       les paquets opcode 0 "init" de UAUDP
  - ``ua3g``         : liste des messages UA3G bruts portés par le paquet
                       (ex: ``opcode``, ``command_mute``,
                       ``unsolicited_msg_hook_status``) — voir paragraphe
                       dédié ci-dessous
  - ``endpoints``    : src/dst IP+ports (utile côté HOMER pour le mapping)
  - ``timestamps``    : secondes + microsecondes epoch (redondant avec les
                       chunks HEP dédiés, mais pratique dans la payload JSON)
  - ``raw_selected`` : quelques champs de niveau frame/ip pour le débogage

Le champ ``noe`` est conservé (liste d'événements) quand il existe — les
captures d'exemple ``ua3g_freeseating_ipv4.pcap`` contiennent effectivement
des événements NOE (objectid, method, property, class...) que le normaliseur
extrait avec le préfixe ``noe_noe_`` retiré pour des noms de champs propres.
Chaque événement reçoit en plus, quand résolvable : ``class_name``,
``method_name``, ``server_name``, ``event_name``, ``errcode_name``,
``property_name``.

Le champ ``ua3g`` suit le même principe (liste de messages) — tshark -T ek
imbrique toujours le(s) message(s) UA3G d'un paquet sous une clé ``ua3g``
(dict si un seul message, liste si plusieurs sont empilés dans le même
paquet UAUDP opcode 7 : observé jusqu'à 3 dans les captures d'exemple),
jamais en clés ``ua3g_ua3g_*`` à plat directement sous ``ua``. Le préfixe
``ua3g_ua3g_`` est retiré de chaque message pour des noms de champs propres.

Comme pour NOE, un libellé protocolaire officiel (``opcode_name``) est ajouté
quand résolvable — mais l'opcode UA3G est ambigu sans connaître le **sens**
du message (voir ``oxo_hep_bridge.ua_opcode_names`` : System->Terminal et
Terminal->System partagent le même nom de champ tshark pour deux tables
différentes). Le sens est déduit des ports UDP/TCP du paquet
(``_infer_ua3g_direction``, sourcé de la préférence Wireshark par défaut
``UAUDP_PORT_RANGE``) ; si les deux ports en sont hors et hors du port
serveur connu, aucun nom n'est ajouté plutôt que de deviner.

Cas particulier : un message UA3G opcode 0x13 ("IP Device Routing") porte
lui-même un octet de sous-commande, exposé par tshark sous deux noms de
champs distincts et déjà auto-disambiguïsés par sens (``ip`` côté
System->Terminal, ``ip_cs`` côté Terminal->System — jamais les deux dans le
même message). ``annotate_ua3g_message`` y ajoute ``ip_name``/``ip_cs_name``
quand résolvable, sourcés depuis ``oxo_hep_bridge.ua_opcode_names``
(``UA3G_IP_DEVICE_ROUTING_SYS_NAMES``/``..._CS_NAMES``), sans passer par la
déduction de sens par port utilisée pour ``opcode_name`` — le nom du champ
suffit ici à lever l'ambiguïté.

Sous-cas de ce dernier : les sous-commandes 0x09 ("Get Parameters Value",
requête système), 0x02 ("Get Parameters Value Response", réponse terminal),
0x0A ("Set Parameters Value", requête système) et 0x11 ("Free Seating",
requête système) portent chacune une **liste** d'identifiants de paramètre
(un message peut en demander/renvoyer/fixer plusieurs). ``annotate_ua3g_
message`` y ajoute ``ip_get_param_req_parameter_names``/
``ip_cs_cmd02_parameter_names``/``ip_set_param_req_parameter_names``/
``ip_freeseating_parameter_names`` via
``oxo_hep_bridge.ua_opcode_names.decode_names`` (résolution élément par
élément, liste alignée sur le champ source) plutôt que ``decode_name``. Les
deux premiers champs partagent la même table de résolution
(``UA3G_IP_DEVICE_ROUTING_PARAMETER_NAMES``) ; les deux derniers (0x0A et
0x11) utilisent chacun une table dédiée et distincte
(``UA3G_IP_DEVICE_ROUTING_SET_PARAMETER_NAMES``/``..._FREESEATING_
PARAMETER_NAMES``) — voir le docstring de ``oxo_hep_bridge.ua_opcode_names``
pour le détail.
"""

from __future__ import annotations

import json
from typing import Any

from loguru import logger

from oxo_hep_bridge.fields import as_int, as_str, build_correlation_id, pick
from oxo_hep_bridge.ua_opcode_names import (
    NOE_CLASS_NAMES,
    NOE_ERRCODE_NAMES,
    NOE_EVENT_NAMES,
    NOE_METHOD_NAMES,
    NOE_PROPERTY_NAMES,
    NOE_SERVER_NAMES,
    UA3G_IP_DEVICE_ROUTING_CS_NAMES,
    UA3G_IP_DEVICE_ROUTING_FREESEATING_PARAMETER_NAMES,
    UA3G_IP_DEVICE_ROUTING_PARAMETER_NAMES,
    UA3G_IP_DEVICE_ROUTING_SET_PARAMETER_NAMES,
    UA3G_IP_DEVICE_ROUTING_SYS_NAMES,
    UA3G_OPCODE_SYS_NAMES,
    UA3G_OPCODE_TERM_NAMES,
    UAUDP_OPCODE_NAMES,
    UAUDP_TERMINAL_DEFAULT_PORTS,
    decode_name,
    decode_names,
)

# Prefixes tshark -T ek observés (sans -e, double préfixage protocole_champ)
_UAUDP_PREFIX = "uaudp_uaudp_"
_UA3G_PREFIX = "ua3g_ua3g_"

# Champs UAUDP "scalaires" présents dans les captures réelles
_UAUDP_SCALAR_FIELDS = (
    "opcode",
    "sntseq",
    "expseq",
    "version",
    "length",
    "type",
    "udp_lost",
    "keepalive",
    "superfast_connect",
    "udp_lost_reinit",
    "window_size",
    "mtu",
    "qos_ip_tos",
)

# Champs de niveau frame/ip conservés pour le débogage dans raw_selected
_RAW_FIELDS = ("frame_frame_number", "frame_frame_len", "ip_ip_ttl", "ip_ip_dsfield_dscp")


def extract_uaudp_fields(flat: dict[str, Any]) -> dict[str, Any]:
    """Extrait les champs UAUDP scalaires dans un dict propre {nom: valeur}.

    Les champs listés (ex: ``type``/``length`` quand plusieurs paramètres QoS
    sont empilés) sont conservés comme listes pour ne pas perdre d'information.
    """
    logger.trace("extract_uaudp_fields() appelée")
    out: dict[str, Any] = {}
    for k, v in flat.items():
        if not k.startswith(_UAUDP_PREFIX):
            continue
        name = k[len(_UAUDP_PREFIX) :]
        if name in _UAUDP_SCALAR_FIELDS:
            out[name] = v
    logger.trace("extract_uaudp_fields() retourne | {} champ(s)", len(out))
    return out


def extract_raw_selected(flat: dict[str, Any]) -> dict[str, Any]:
    """Sélectionne quelques champs frame/ip utiles au débogage."""
    return {k: flat[k] for k in _RAW_FIELDS if k in flat}


# (champ événement NOE, table de résolution, nom du champ *_name ajouté)
_NOE_NAME_LOOKUPS: tuple[tuple[str, dict[int, str], str], ...] = (
    ("class", NOE_CLASS_NAMES, "class_name"),
    ("method", NOE_METHOD_NAMES, "method_name"),
    ("server", NOE_SERVER_NAMES, "server_name"),
    ("event", NOE_EVENT_NAMES, "event_name"),
    ("errcode", NOE_ERRCODE_NAMES, "errcode_name"),
    ("property", NOE_PROPERTY_NAMES, "property_name"),
)


def annotate_noe_event(event: dict[str, Any]) -> dict[str, Any]:
    """Ajoute les libellés protocolaires officiels (``*_name``) à un
    événement NOE quand la valeur numérique correspondante est résolvable
    dans les tables sourcées du dissecteur Wireshark ALE (voir
    ``oxo_hep_bridge.ua_opcode_names``). N'écrase jamais un champ existant ;
    n'ajoute rien si la valeur est absente ou non résolvable.
    """
    logger.trace("annotate_noe_event() appelée")
    out = dict(event)
    for field, table, name_field in _NOE_NAME_LOOKUPS:
        if name_field in out:
            continue
        resolved = decode_name(table, pick(out.get(field)))
        if resolved is not None:
            out[name_field] = resolved
    logger.trace("annotate_noe_event() retourne | événement annoté")
    return out


def _infer_ua3g_direction(flat: dict[str, Any]) -> dict[int, str] | None:
    """Déduit la table d'opcodes UA3G à utiliser (sys ou term) à partir des
    ports UDP/TCP du paquet, sur le modèle de ``dissect_uaudp()`` côté
    Wireshark (``value_is_in_range(ua_udp_range, ...)``) : si le port source
    appartient à ``UAUDP_TERMINAL_DEFAULT_PORTS``, le message vient du
    terminal ; si c'est le port destination, il vient du système. Retourne
    None si aucun des deux ports n'y figure — pas de sens deviné sans base
    sourcée (voir docstring du module).
    """
    logger.trace("_infer_ua3g_direction() appelée")
    srcport = as_int(flat.get("udp_udp_srcport") or flat.get("tcp_tcp_srcport"), default=-1)
    dstport = as_int(flat.get("udp_udp_dstport") or flat.get("tcp_tcp_dstport"), default=-1)
    if srcport in UAUDP_TERMINAL_DEFAULT_PORTS:
        logger.trace("_infer_ua3g_direction() retourne | table term")
        return UA3G_OPCODE_TERM_NAMES
    if dstport in UAUDP_TERMINAL_DEFAULT_PORTS:
        logger.trace("_infer_ua3g_direction() retourne | table sys")
        return UA3G_OPCODE_SYS_NAMES
    logger.trace("_infer_ua3g_direction() retourne | None (sens indéterminé)")
    return None


# (champ sous-commande du message UA3G opcode 0x13 "IP Device Routing",
# table de résolution, nom du champ *_name ajouté). Contrairement à
# "opcode" ci-dessus, ces deux champs tshark sont déjà auto-disambiguïsés
# par le dissecteur ALE selon le sens du message : "ip" (hf_ua3g_ip,
# "ua3g.ip") n'est émis que côté System->Terminal (case
# SC_IP_DEVICE_ROUTING) et "ip_cs" (hf_ua3g_ip_cs, "ua3g.ip.cs") que côté
# Terminal->System (case CS_IP_DEVICE_ROUTING) — jamais les deux dans le
# même message. Pas besoin de la déduction par port utilisée pour "opcode"
# (_infer_ua3g_direction) : résolus indépendamment de opcode_table.
_UA3G_IP_DEVICE_ROUTING_LOOKUPS: tuple[tuple[str, dict[int, str], str], ...] = (
    ("ip", UA3G_IP_DEVICE_ROUTING_SYS_NAMES, "ip_name"),
    ("ip_cs", UA3G_IP_DEVICE_ROUTING_CS_NAMES, "ip_cs_name"),
)

# (champ tshark répété "liste d'identifiants de paramètre", table de
# résolution, nom du champ *_names ajouté). Sous-cas de "IP Device Routing"
# (voir _UA3G_IP_DEVICE_ROUTING_LOOKUPS ci-dessus) où le message porte
# plusieurs identifiants plutôt qu'un seul : sous-commande 0x09
# "Get Parameters Value" (requête système, champ "ip" == 9) et sous-commande
# 0x02 "Get Parameters Value Response" (réponse terminal, champ "ip_cs" ==
# 2) — ces deux-là partagent la même table côté dissecteur
# (`ip_device_routing_cmd_get_param_req_vals[]`) — plus sous-commande 0x0A
# "Set Parameters Value" (requête système, champ "ip" == 10) et sous-
# commande 0x11 "Free Seating" (requête système, champ "ip" == 17), qui
# utilisent chacune une table dédiée et DISTINCTE
# (`ip_device_routing_cmd_set_param_req_vals`/
# `ip_device_routing_cmd_freeseating_vals` — voir le docstring de
# `ua_opcode_names` pour le détail, notamment le doublement consécutif des
# valeurs observé aussi sur ces deux champs). Les quatre sont résolus
# élément par élément par decode_names() plutôt que decode_name()+pick().
_UA3G_IP_DEVICE_ROUTING_PARAMETER_LOOKUPS: tuple[tuple[str, dict[int, str], str], ...] = (
    (
        "ip_get_param_req_parameter",
        UA3G_IP_DEVICE_ROUTING_PARAMETER_NAMES,
        "ip_get_param_req_parameter_names",
    ),
    (
        "ip_cs_cmd02_parameter",
        UA3G_IP_DEVICE_ROUTING_PARAMETER_NAMES,
        "ip_cs_cmd02_parameter_names",
    ),
    (
        "ip_set_param_req_parameter",
        UA3G_IP_DEVICE_ROUTING_SET_PARAMETER_NAMES,
        "ip_set_param_req_parameter_names",
    ),
    (
        "ip_freeseating_parameter",
        UA3G_IP_DEVICE_ROUTING_FREESEATING_PARAMETER_NAMES,
        "ip_freeseating_parameter_names",
    ),
)


def annotate_ua3g_message(
    message: dict[str, Any], opcode_table: dict[int, str] | None
) -> dict[str, Any]:
    """Ajoute les libellés protocolaires officiels résolvables à un message
    UA3G, sans jamais écraser un champ existant :

    - ``opcode_name``, quand ``opcode_table`` est fourni (sens déterminé,
      voir ``_infer_ua3g_direction``) et que la valeur numérique ``opcode``
      y est résolvable ;
    - ``ip_name``/``ip_cs_name`` pour la sous-commande d'un message opcode
      0x13 "IP Device Routing" (champs ``ip``/``ip_cs``, voir
      ``_UA3G_IP_DEVICE_ROUTING_LOOKUPS``) — résolus indépendamment du sens
      déjà déterminé par le nom du champ tshark lui-même ;
    - ``ip_get_param_req_parameter_names``/``ip_cs_cmd02_parameter_names``/
      ``ip_set_param_req_parameter_names``/``ip_freeseating_parameter_names``
      pour les identifiants de paramètre des sous-commandes 0x09/0x02/0x0A/
      0x11 de "IP Device Routing"
      (voir ``_UA3G_IP_DEVICE_ROUTING_PARAMETER_LOOKUPS``) — champs répétés,
      résolus élément par élément (liste alignée, ``None`` pour les
      identifiants non résolvables) plutôt qu'une seule valeur.
    """
    logger.trace("annotate_ua3g_message() appelée")
    out = dict(message)
    if opcode_table is not None and "opcode_name" not in out:
        resolved = decode_name(opcode_table, pick(out.get("opcode")))
        if resolved is not None:
            out["opcode_name"] = resolved
    for field, table, name_field in _UA3G_IP_DEVICE_ROUTING_LOOKUPS:
        if name_field in out:
            continue
        resolved = decode_name(table, pick(out.get(field)))
        if resolved is not None:
            out[name_field] = resolved
    for field, param_table, names_field in _UA3G_IP_DEVICE_ROUTING_PARAMETER_LOOKUPS:
        if names_field in out:
            continue
        resolved_names = decode_names(param_table, out.get(field))
        if resolved_names is not None:
            out[names_field] = resolved_names
    logger.trace("annotate_ua3g_message() retourne | message annoté")
    return out


def build_semantic_payload(flat: dict[str, Any]) -> dict[str, Any]:
    """Construit la payload JSON sémantique à partir d'un paquet aplati tshark.

    Retourne un dict structuré (à sérialiser en JSON par l'appelant). Toujours
    non vide si le paquet contient au moins un champ UAUDP/UA3G/NOE.
    """
    logger.trace("build_semantic_payload() appelée")
    uaudp = extract_uaudp_fields(flat)
    # les champs QoS (version, window_size, mtu...) sont déjà dans uaudp sous
    # leur nom simple ; on les extrait du bloc uaudp pour les déplacer dans une
    # section "qos" dédiée, et on les retire de uaudp pour éviter le doublon.
    qos_keys = (
        "version",
        "length",
        "type",
        "udp_lost",
        "keepalive",
        "superfast_connect",
        "udp_lost_reinit",
        "window_size",
        "mtu",
        "qos_ip_tos",
    )
    qos: dict[str, Any] = {k: as_str(pick(uaudp.pop(k))) for k in qos_keys if k in uaudp}
    if "opcode" in uaudp:
        opcode_name = decode_name(UAUDP_OPCODE_NAMES, pick(uaudp["opcode"]))
        if opcode_name is not None:
            uaudp["opcode_name"] = opcode_name
    # tshark -T ek imbrique toujours le(s) message(s) UA3G sous une clé
    # "ua3g" (dict si un seul message, liste si plusieurs sont empilés dans
    # le même paquet) — jamais de clés "ua3g_ua3g_*" à plat directement sous
    # "ua". Même mécanisme que "noe" ci-dessous.
    ua3g_raw = flat.get("ua3g")
    if isinstance(ua3g_raw, list):
        ua3g_messages = [m for m in ua3g_raw if isinstance(m, dict)]
    elif isinstance(ua3g_raw, dict):
        ua3g_messages = [ua3g_raw]
    else:
        ua3g_messages = []
    ua3g = [
        {k[len(_UA3G_PREFIX) :] if k.startswith(_UA3G_PREFIX) else k: v for k, v in m.items()}
        for m in ua3g_messages
    ]
    if ua3g:
        opcode_table = _infer_ua3g_direction(flat)
        ua3g = [annotate_ua3g_message(m, opcode_table) for m in ua3g]
    noe = flat.get("noe")
    if isinstance(noe, list):
        noe_events = [n for n in noe if isinstance(n, dict)]
    elif isinstance(noe, dict):
        noe_events = [noe]
    else:
        noe_events = []
    # retirer le préfixe "noe_noe_" des clés pour des noms de champs propres
    noe_events = [
        {k[len("noe_noe_") :] if k.startswith("noe_noe_") else k: v for k, v in ev.items()}
        for ev in noe_events
    ]
    # ajouter les libellés protocolaires officiels (class_name, method_name...)
    noe_events = [annotate_noe_event(ev) for ev in noe_events]

    payload: dict[str, Any] = {
        "uaudp": uaudp,
        "endpoints": {
            "src": {
                "ip": as_str(flat.get("ip_ip_src") or flat.get("ipv6_ipv6_src")),
                "port": as_int(flat.get("udp_udp_srcport") or flat.get("tcp_tcp_srcport")),
            },
            "dst": {
                "ip": as_str(flat.get("ip_ip_dst") or flat.get("ipv6_ipv6_dst")),
                "port": as_int(flat.get("udp_udp_dstport") or flat.get("tcp_tcp_dstport")),
            },
        },
        "correlation_id": build_correlation_id(flat),
        "raw_selected": extract_raw_selected(flat),
    }

    if qos:
        payload["qos"] = qos
    if ua3g:
        payload["ua3g"] = ua3g
    if noe_events:
        payload["noe"] = noe_events

    logger.trace("build_semantic_payload() retourne | payload construite")
    return payload


def encode_semantic_payload(flat: dict[str, Any]) -> bytes | None:
    """Construit et sérialise la payload sémantique en bytes JSON UTF-8.

    Retourne None si le paquet ne contient aucune donnée UA exploitable
    (ni UAUDP, ni UA3G, ni NOE) — l'appelant doit alors ignorer le paquet.
    """
    logger.trace("encode_semantic_payload() appelée")
    has_uaudp = any(k.startswith(_UAUDP_PREFIX) for k in flat)
    has_ua3g = isinstance(flat.get("ua3g"), dict | list)
    has_noe = isinstance(flat.get("noe"), dict | list)
    if not (has_uaudp or has_ua3g or has_noe):
        logger.trace("encode_semantic_payload() retourne | None (aucune donnée UA)")
        return None
    payload = build_semantic_payload(flat)
    encodage = json.dumps(payload, ensure_ascii=False, default=str).encode("utf-8")
    logger.trace("encode_semantic_payload() retourne | payload JSON")
    return encodage
