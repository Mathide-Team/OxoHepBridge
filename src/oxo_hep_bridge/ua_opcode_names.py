#!/usr/bin/env python3
"""Dictionnaires de noms officiels UAUDP/NOE, sourcés depuis le dissecteur
Wireshark ``packet-uaudp.c`` / ``packet-noe.c`` (Alcatel-Lucent Enterprise,
Lars Ruoff <lars.ruoff@alcatel-lucent.com>, upstream Wireshark, licence
GPL v2+).

Contexte projet — ceci lève partiellement le point ouvert documenté dans
``docs/noe-ua3g-homer-mapping.md`` §6 (« aucune source officielle ALE » pour
un mapping opcode → nom). Ces tables sont un **dictionnaire de nommage
protocolaire officiel** (valeur numérique → libellé tel qu'émis par le
dissecteur), PAS un mapping métier vers des événements d'appel SIP — cette
distinction reste importante, voir le docstring de ``semantics.py`` et
``docs/noe-ua3g-homer-mapping.md`` §7 pour ce qui reste hors périmètre
(corrélation NOE ↔ Call-ID SIP, notamment).

Extraction : les tables ci-dessous sont générées à partir des macros
``#define``/``enum`` et des tableaux ``value_string`` du code source fourni
(cf. session de suivi, CHANGELOG.md) — pas de valeur inventée ni déduite.
Vérifiées par recoupement avec les captures d'exemple du projet
(``tests/fixtures/ua3g_freeseating_ipv4.ek.ndjson``) : ex. classe 128 →
"FrameBox", méthode 2 → "SetProperty", serveur 21 → "Call Server", propriété
40 → "visible" — cohérent avec les valeurs brutes réellement observées.

Portée volontairement limitée :
  - ``NOE_PROPERTY_NAMES`` est un espace de nommage globalement partagé côté
    dissecteur (un même entier renvoie le même libellé quelle que soit la
    classe) — vérifié par la construction du tableau ``val_str_props`` dans
    le source (pas de table par-classe dans le dissecteur lui-même). Le nom
    ne décrit donc que le *type de champ générique*, pas sa sémantique dans
    le contexte d'une classe donnée.
  - ``UA3G_OPCODE_SYS_NAMES``/``UA3G_OPCODE_TERM_NAMES`` (opcodes UA3G,
    ``packet-ua3g.c``) sont deux tables **distinctes et non fusionnables** :
    le dissecteur ALE réutilise le même nom de champ tshark (``ua3g.opcode``)
    pour deux tableaux ``value_string`` différents selon le sens du message
    (``opcodes_vals_sys`` System→Terminal, préfixe ``SC_`` ; et
    ``opcodes_vals_term`` Terminal→System, préfixe ``CS_``) — leurs espaces de
    valeurs se recouvrent (ex: opcode 3 = "Software Reset" côté système mais
    "Digital Dialed" côté terminal), donc une table unique donnerait un nom
    silencieusement faux la moitié du temps. ``UAUDP_TERMINAL_DEFAULT_PORTS``
    (``UAUDP_PORT_RANGE`` = ``"32000,32512"`` dans ``packet-uaudp.c``, la
    valeur par défaut du préférence Wireshark utilisée par ``dissect_uaudp()``
    pour choisir le sens quand aucune adresse serveur n'est configurée) permet
    de déduire le sens à partir des ports UDP déjà disponibles dans la payload
    (``semantics.build_semantic_payload``) : si le port source appartient à
    cet ensemble, le message vient du terminal (Terminal→System) ; si c'est le
    port destination, il vient du système (System→Terminal). Vérifié sur les
    503 messages UA3G réels de ``ua3g_freeseating_ipv4/ipv6.pcap`` : dans ces
    captures le système utilise le port 32640 (hors de l'ensemble par défaut,
    nécessite ``--decode-as`` — voir docs/architecture.md) et le terminal le
    port 32512 (l'un des deux ports par défaut) — les deux tables résolvent
    alors correctement 100% des opcodes observés (ex: 19→"IP Device Routing"
    dans les deux sens car ``SC_IP_DEVICE_ROUTING``/``CS_IP_DEVICE_ROUTING``
    valent tous deux 0x13 ; 159→"Unsolicited Message" et 33→"Version
    Information" uniquement résolus côté terminal, cohérent avec leur usage
    réel). Si aucun des deux ports n'appartient à l'ensemble par défaut (sens
    non déterminable sans configuration serveur explicite), aucun nom n'est
    ajouté — pas de déduction inventée au-delà de ce que Wireshark ferait
    lui-même par défaut.
  - ``UA3G_IP_DEVICE_ROUTING_SYS_NAMES``/``UA3G_IP_DEVICE_ROUTING_CS_NAMES``
    couvrent le cas particulier de l'opcode UA3G 0x13 ("IP Device Routing") :
    ce message porte lui-même un octet de sous-commande, sourcé de
    ``str_command_ip_device_routing[]``/``str_command_cs_ip_device_routing[]``
    (``packet-ua3g.c``, §IP Device Routing). Contrairement à l'opcode
    principal ci-dessus, ces deux tables n'ont **pas** besoin de la
    déduction par port (``UAUDP_TERMINAL_DEFAULT_PORTS``) : le dissecteur
    ALE les expose sous deux champs tshark distincts et déjà
    auto-disambiguïsés selon le sens du message — ``ua3g.ip`` (``hf_ua3g_ip``,
    System→Terminal, ``case SC_IP_DEVICE_ROUTING``) et ``ua3g.ip.cs``
    (``hf_ua3g_ip_cs``, Terminal→Système, ``case CS_IP_DEVICE_ROUTING``) —
    jamais les deux à la fois dans un même message. Vérifié sur les messages
    opcode 0x13 réels de ``ua3g_freeseating_ipv4/ipv6.ek.ndjson`` : valeurs
    ``ip`` observées 4, 5, 6, 9, 10, 16, 17 (ex: 5→"Start Tone", 6→"Stop
    Tone", 17→"Free Seating" — cohérent avec le nom du fichier de capture,
    une fonctionnalité "sonnerie libre") et valeurs ``ip_cs`` observées 0, 2
    (0→"Init", 2→"Get Parameters Value Response").
  - ``UA3G_IP_DEVICE_ROUTING_PARAMETER_NAMES`` complète le sous-cas des
    sous-commandes 0x09 ("Get Parameters Value", requête système) et 0x02
    ("Get Parameters Value Response", réponse terminal) de "IP Device
    Routing" : contrairement aux tables ci-dessus, ces deux champs tshark
    (``ua3g.ip.get_param_req.parameter``/``ua3g.ip.cs.cmd02.parameter``)
    portent chacun une **liste** d'identifiants de paramètre (un message
    peut en demander/renvoyer plusieurs), résolue via ``decode_names()``
    plutôt que ``decode_name()``. Les deux champs partagent la même table
    ``ip_device_routing_cmd_get_param_req_vals[]`` côté dissecteur — pas de
    piège de sens à gérer ici, contrairement à ``ip``/``ip_cs`` ci-dessus.
  - ``UA3G_IP_DEVICE_ROUTING_SET_PARAMETER_NAMES`` couvre la sous-commande
    0x0A ("Set Parameters Value", requête système) volontairement laissée
    de côté ci-dessus — champ tshark ``ua3g.ip.set_param_req.parameter``
    (``hf_ua3g_ip_device_routing_set_param_req_parameter``), table dédiée
    et **distincte** ``ip_device_routing_cmd_set_param_req_vals[]``/
    ``..._vals_ext`` (40 entrées, ``BASE_HEX|BASE_EXT_STRING`` — ne pas
    confondre avec ``ip_device_routing_cmd_get_param_req_vals[]`` ci-dessus
    malgré la proximité du nom de champ tshark). Également une **liste**
    résolue par ``decode_names()`` — et, point notable découvert en lisant
    le code de dissection (pas seulement la table ``value_string``) :
    chaque identifiant y est lui aussi dissecté DEUX FOIS de suite sur le
    même hf (``proto_tree_add_uint_format`` puis ``proto_tree_add_item``,
    ``packet-ua3g.c`` lignes ~1577/1582 — même motif que ``cmd02``
    ci-dessus), mais ici côté **requête système**, pas réponse terminal :
    le doublement dépend donc du champ précis dans le dissecteur, pas du
    sens du message comme le laissait supposer le seul cas observé en
    session 33. Vérifié à la fois dans le code source et sur les fixtures
    réelles (``ua3g_freeseating_ipv4/ipv6.ek.ndjson``, ex: liste brute
    ``[3, 3, 4, 4, 5, 5]`` pour un message ``ip=10`` "Set Parameters
    Value").
  - ``UA3G_IP_DEVICE_ROUTING_FREESEATING_PARAMETER_NAMES`` couvre la
    sous-commande 0x11 ("Free Seating", requête système) — le candidat
    unique laissé en suspens à la fin de la session précédente. Champ
    tshark ``ua3g.ip.freeseating.parameter``
    (``hf_ua3g_ip_device_routing_freeseating_parameter``), sourcé de
    ``ip_device_routing_cmd_freeseating_vals[]`` (table ``VALS()`` simple,
    4 entrées seulement — pas de variante ``_ext`` contrairement à
    ``SET_PARAMETER_NAMES``). Structurellement proche de
    ``ua3g.ip.set_param_req.parameter`` : même motif de boucle de
    dissection, et le doublement consécutif d'identifiant s'y vérifie
    aussi (liste brute ``[0, 0, 1, 1]`` sur la fixture ipv4, ``[0, 0, 1,
    1, 2, 2]`` sur ipv6 — jamais un identifiant isolé). Résolue par
    ``decode_names()`` comme les autres champs répétés de cette famille.
"""

from __future__ import annotations

from typing import Any

from loguru import logger

UAUDP_OPCODE_NAMES: dict[int, str] = {  # uaudp_opcode_str[] (packet-uaudp.c)
    0: "Connect",
    1: "Connect ACK",
    2: "Release",
    3: "Release ACK",
    4: "Keepalive",
    5: "Keepalive ACK",
    6: "NACK",
    7: "Data",
}
# Opcodes 16-23 (0x10-0x17) : NON présents dans uaudp_opcode_str[] (Wireshark
# affiche "Opcode: Unknown (N)" en display natif, vérifié via `tshark -V`).
# Observés dans sample_captures/uaudp_ipv6.pcap : chaque valeur = opcode de
# base (0-7) + bit 0x10, sur un canal local distinct (src_port==dst_port==
# 32640) avec des cadences très régulières (~158,5s pour 16/17,~15,1s pour
# 20/21) — hypothèse non officielle, détail et données brutes dans
# docs/noe-ua3g-homer-mapping.md §6ter. À ne PAS ajouter ici tant que ce
# n'est pas confirmé par une source officielle : ce dict reflète uniquement
# la table Wireshark upstream, pas nos déductions.
# Point notable pour ce module : les trames opcode 23 (Data+0x10) portent des
# octets qui ressemblent à un message NOE (property/server), mais Wireshark
# arrête la dissection à l'opcode inconnu — extract_noe_events() ne verra
# donc rien pour ces paquets (aucune couche ua/noe produite par tshark).

NOE_CLASS_NAMES: dict[int, str] = {  # val_str_class[] (packet-noe.c)
    0: "Context",
    1: "Terminal",
    2: "Keyboard",
    3: "AudioConfig",
    4: "Security",
    5: "Leds",
    6: "Screen",
    7: "Date",
    8: "AOMV",
    9: "Bluetooth",
    12: "Callstate",
    128: "FrameBox",
    129: "TabBox",
    130: "ListBox",
    131: "ActionlistBox",
    132: "TextBox",
    133: "ActionBox",
    134: "InputBox",
    135: "CheckBox",
    136: "DateBox",
    137: "TimerBox",
    138: "PopupBox",
    139: "DialogBox",
    140: "SliderBar",
    141: "ProgressBar",
    142: "ImageBox",
    143: "IconBox",
    144: "AOMVBox",
    145: "TelephonicBox",
    146: "Keyboard_context",
    147: "AOMEL",
    148: "AOM10",
    149: "AOM40",
    150: "IdleTimer",
    151: "TelephonicBoxItem",
    152: "Bluetooth_device",
    153: "HeaderBox",
    154: "ime_context",
}

NOE_METHOD_NAMES: dict[int, str] = {  # methods_vals[] (packet-noe.c)
    0: "Create",
    1: "Delete",
    2: "SetProperty",
    3: "GetProperty",
    4: "Notify",
    5: "DeleteItem",
    6: "InsertItem",
}

NOE_SERVER_NAMES: dict[int, str] = {  # servers_vals[] (packet-noe.c)
    21: "Call Server",
    22: "Presentation Server",
}

NOE_EVENT_NAMES: dict[int, str] = {  # val_str_event[] (packet-noe.c)
    0: "EVT_CONTEXT_SWITCH",
    1: "EVT_RESET",
    2: "EVT_KEY_PRESS",
    3: "EVT_KEY_RELEASE",
    4: "EVT_KEY_SHORTPRESS",
    5: "EVT_KEY_LONGPRESS",
    6: "EVT_ONHOOK",
    7: "EVT_OFFHOOK",
    8: "EVT_HELP",
    9: "EVT_WIDGETS_GC",
    10: "EVT_ERROR_PROTOCOL",
    11: "EVT_ERROR_CREATE",
    12: "EVT_ERROR_DELETE",
    13: "EVT_ERROR_SET_PROPERTY",
    14: "EVT_ERROR_GET_PROPERTY",
    15: "EVT_SUCCESS_CREATE",
    16: "EVT_SUCCESS_DELETE",
    17: "EVT_SUCCESS_SET_PROPERTY",
    18: "EVT_ERROR_INSERT_ITEM",
    19: "EVT_ERROR_DELETE_ITEM",
    20: "EVT_SUCCESS_INSERT_ITEM",
    21: "EVT_DEVICE_PRESENCE",
    22: "EVT_KEY_LINE",
    23: "EVT_SUCCESS_DELETE_ITEM",
    24: "EVT_BT_BONDING_RESULT",
    25: "EVT_BT_KEY_SHORTPRESS",
    26: "EVT_BT_KEY_LONGPRESS",
    27: "EVT_BT_KEY_VERYLONGPRESS",
    28: "EVT_LOCAL_APPLICATION",
    29: "EVT_WARNING_CREATE",
    30: "EVT_WARNING_SET_PROPERTY",
    31: "EVT_ARP_SPOOFING",
    32: "EVT_CHAR_NOT_FOUND",
    34: "EVT_QOS_TICKET",
    35: "EVT_UA3_ERROR",
    128: "EVT_TABBOX",
    129: "EVT_LISTBOX",
    130: "EVT_LISTBOX_FIRST",
    131: "EVT_LISTBOX_LAST",
    132: "EVT_ACTIONLISTBOX",
    133: "EVT_ACTIONBOX",
    134: "EVT_INPUTBOX",
    135: "EVT_INPUTBOX_FOCUS_LOST",
    136: "EVT_CHECKBOX",
    137: "EVT_TIMERBOX",
    138: "EVT_POPUPBOX_TIMEOUT",
    139: "EVT_DIALOGBOX",
    140: "EVT_SLIDERBAR",
    141: "EVT_PROGRESSBAR",
    142: "EVT_AOMVBOX",
    143: "EVT_TELEPHONICBOX_FOCUS",
    144: "EVT_AOM_INSERTED",
    145: "EVT_AOM_REMOVED",
    146: "EVT_AOM_KEY_PRESS",
    147: "EVT_IDLETIMER",
    148: "EVT_GET_PROPERTY_RESULT",
    149: "EVT_AOM_KEY_RELEASE",
    150: "EVT_POPUPBOX_DISMISSED",
    151: "EVT_DIALOGBOX_TIMEOUT",
    152: "EVT_DIALOGBOX_DISMISSED",
    153: "EVT_BT_BONDED_DEVICE",
    154: "EVT_BT_INQUIRY_RESULT",
    155: "EVT_BT_NAME_DISCOVERY",
    156: "EVT_IME_REMOTEOPEN",
    158: "EVT_BT_BATTERY",
    159: "EVT_IME_LIST",
    160: "EVT_IME_CHANGE",
    161: "EVT_IME_OPEN",
    162: "EVT_TELEPHONICBOX_EVENT",
    163: "EVT_ACTLISTBOX_TIMEOUT",
    164: "EVT_ACTLISTBOX_DISMISSED",
}

NOE_ERRCODE_NAMES: dict[int, str] = {  # errcode_vals[] (packet-noe.c)
    0: "An invalid method opcode was received",
    1: "An invalid class opcode was received",
    2: "Trying to create or delete a static class",
    3: "Trying to create an existing object",
    4: "Property opcode doesn't exist in specified class",
    5: "Bad property index (array overflow)",
    6: "Short message or bad property length",
    7: "A required property was not specified in create method",
    8: "Bad property value",
    9: "Trying to set a read-only property",
    10: "The specified object doesn't exist (delete, setProperty or getProperty methods)",
    11: "Invalid container",
    12: "Property value < property minimum value",
    13: "Property value > property maximum value",
    14: "Positive ack requested with a getProperty method",
    15: "The specified property is not implemented",
    16: "Invalid class specified with insertItem and deleteItem",
    17: "Invalid property specified with insertItem and deleteItem",
    18: "Invalid UTF8 value in UA message",
    128: "Decoder queue is full",
    129: "A maximum of 256 properties can be received in a setProperty method",
    130: "Internal error",
}

NOE_PROPERTY_NAMES: dict[int, str] = {  # val_str_props[] (packet-noe.c)
    0: "objectid",
    1: "ownership",
    2: "reset_mode",
    3: "mtu",
    4: "negative_ack",
    5: "type",
    6: "help_timeout",
    7: "longpress",
    8: "count",
    9: "eventmode",
    10: "numpad_ownership",
    11: "navigator_ownership",
    12: "telephony_ownership",
    13: "progkeys_ownership",
    14: "alphakeys_ownership",
    15: "numpad_eventmode",
    16: "onoff",
    17: "bpp",
    18: "w",
    19: "h",
    20: "contrast",
    21: "clearscreen",
    24: "year",
    25: "month",
    26: "day",
    27: "m",
    28: "s",
    29: "enable",
    30: "address",
    33: "name",
    36: "anchorid",
    37: "grid",
    38: "x",
    39: "y",
    40: "visible",
    41: "border",
    42: "fontid",
    43: "active",
    44: "halign",
    45: "valign",
    46: "size",
    47: "mode",
    48: "showevent",
    49: "showactive",
    54: "icon",
    55: "label",
    56: "value",
    57: "password",
    58: "cursor",
    59: "mask",
    60: "qos_ticket",
    61: "focus",
    62: "state",
    63: "format",
    64: "incdec",
    65: "value_notify",
    66: "timeout",
    67: "min",
    68: "max",
    69: "data",
    70: "custversion",
    71: "L10Nversion",
    72: "append",
    73: "shortpress",
    74: "autorepeat",
    75: "repetition",
    76: "vsplit",
    77: "accesskey",
    78: "realcount",
    79: "start",
    80: "modal",
    81: "session_timeout",
    82: "softkeys_ownership",
    83: "ringings_count",
    84: "cod",
    85: "bonded",
    86: "link_key",
    87: "pin",
    88: "term_type",
    89: "link_type",
    90: "circular",
    91: "autospread",
    92: "backlight_timeout",
    93: "screensaver_timeout",
    94: "cycling",
    95: "CS_idle_state",
    96: "PS_idle_state",
    97: "bonded_devices",
    98: "serialnum",
    99: "hardversion",
    100: "softversion",
    101: "rom_size",
    102: "ram_size",
    103: "reset_cause",
    104: "cycling_time",
    106: "inputborder",
    107: "disablelongpress",
    108: "all_icons_off",
    109: "all_labels_off",
    110: "widgets_size",
    111: "list_type",
    112: "frame_type",
    113: "bth_ringing",
    114: "URI",
    115: "fetch_timeout",
    116: "mask_subst",
    117: "use_customisation",
    120: "page_active",
    121: "overwrite",
    122: "ime_lock",
    123: "method",
    124: "login",
    125: "binary_suffix",
    126: "binary_count",
    127: "SIPCversion",
    131: "key_ownership",
    132: "key_eventmode",
    133: "value",
    134: "mode",
    135: "color",
    136: "type",
    137: "icon",
    138: "label",
    139: "ownership",
    140: "enable",
    141: "state",
    142: "name",
    143: "number",
    144: "action_icon",
    145: "action_label",
    146: "action_value",
    147: "today",
    148: "tomorrow",
    150: "code",
    151: "data",
    152: "delay_max_handset",
    153: "delay_max_handsfree",
    154: "delay_tx",
    155: "delay_rx",
    156: "pem_data",
    157: "serial_number",
    158: "owner_name",
    159: "issuer_name",
    160: "end_date",
}


UA3G_OPCODE_SYS_NAMES: dict[int, str] = {  # opcodes_vals_sys[] (packet-ua3g.c), System -> Terminal
    0x00: "NOP",
    0x01: "Production Test",
    0x02: "Subdevice Escape To Subdevice",
    0x03: "Software Reset",
    0x04: "IP-Phone Warmstart",
    0x05: "HE Routing Code",
    0x06: "Subdevice Reset",
    0x07: "Loopback On",
    0x08: "Loopback Off",
    0x09: "Video Routing Code",
    0x0B: "Super Message",
    0x0C: "Segment Message",
    0x0D: "Remote UA Routing Code",
    0x0E: "Very Remote UA Routing Code",
    0x0F: "OSI Routing Code",
    0x11: "ABC-A Routing Code",
    0x12: "IBS Routing Code",
    0x13: "IP Device Routing",
    0x14: "Multi-Reflex Hub Routing Code",
    0x17: "Super Message 2",
    0x18: "Debug In Line",
    0x21: "Led Command",
    0x22: "Start Buzzer",
    0x23: "Stop Buzzer",
    0x24: "Enable DTMF",
    0x25: "Disable DTMF",
    0x26: "Clear LCD Display",
    0x27: "LCD Line 1 Commands",
    0x28: "LCD Line 2 Commands",
    0x29: "Main Voice Mode",
    0x2A: "Version Inquiry",
    0x2B: "Are You There?",
    0x2C: "Subdevice Metastate",
    0x2D: "VTA Status Inquiry",
    0x2E: "Subdevice State?",
    0x30: "Download DTMF & Clock Format",
    0x31: "Set Clock",
    0x32: "Voice Channel",
    0x33: "External Ringing",
    0x35: "LCD Cursor",
    0x36: "Download Special Character",
    0x38: "Set Clock/Timer Position",
    0x39: "Set LCD Contrast",
    0x3A: "Audio Idle",
    0x3B: "Set Speaker Volume",
    0x3C: "Beep",
    0x3D: "Sidetone",
    0x3E: "Set Programmable Ringing Cadence",
    0x3F: "Mute",
    0x40: "Feedback",
    0x41: "Key Release",
    0x42: "Trace On",
    0x43: "Trace Off",
    0x44: "Read Peripheral",
    0x45: "Write Peripheral",
    0x46: "All Icons Off",
    0x47: "Icon Command",
    0x48: "Amplified Handset (Boost)",
    0x49: "Audio Config",
    0x4A: "Audio Padded Path",
    0x4B: "Release Radio Link",
    0x4C: "DECT External Handover Routing Code",
    0x4D: "Loudspeaker",
    0x4E: "Announce",
    0x4F: "Ring",
    0x50: "UA Download Protocol",
}

UA3G_OPCODE_TERM_NAMES: dict[
    int, str
] = {  # opcodes_vals_term[] (packet-ua3g.c), Terminal -> System
    0x00: "NOP Acknowledge",
    0x01: "Handset Offhook",
    0x02: "Handset Onhook",
    0x03: "Digital Dialed",
    0x04: "Subdevice Message",
    0x05: "HE Routing Response Code",
    0x06: "Loopback On Acknowledge",
    0x07: "Loopback Off Acknowledge",
    0x09: "Video Routing Response Code",
    0x0A: "Warmstart Acknowledge",
    0x0B: "Super Message",
    0x0C: "Segment Message",
    0x0D: "Remote UA Routing Response Code",
    0x0E: "Very Remote UA Routing Response Code",
    0x0F: "OSI Response Code",
    0x11: "ABC-A Routing Response Code",
    0x12: "IBS Routing Response Code",
    0x13: "IP Device Routing",
    0x17: "Super Message 2",
    0x18: "Debug Message",
    0x20: "Non-Digit Key Pushed",
    0x21: "Version Information",
    0x22: "I'm Here Response",
    0x23: "Response To Status Inquiry",
    0x24: "Subdevice State Response",
    0x26: "Digit Key Released",
    0x27: "Trace On Acknowledge",
    0x28: "Trace Off Acknowledge",
    0x29: "Special Key Status",
    0x2A: "Key Released",
    0x2B: "Peripheral Content",
    0x2D: "TM Key Pushed",
    0x50: "Download Protocol",
    0x9F: "Unsolicited Message",
}

# UAUDP_PORT_RANGE ("32000,32512") dans packet-uaudp.c : valeur par défaut de
# la préférence Wireshark utilisée par dissect_uaudp() pour déduire le sens
# d'un message (System->Terminal / Terminal->System) à partir des ports UDP
# quand aucune adresse serveur n'est configurée explicitement (préférence
# "system_ip", non applicable ici — voir le docstring de ce module).
UAUDP_TERMINAL_DEFAULT_PORTS: frozenset[int] = frozenset({32000, 32512})

UA3G_IP_DEVICE_ROUTING_SYS_NAMES: dict[int, str] = {
    # str_command_ip_device_routing[] (packet-ua3g.c), champ tshark
    # "ua3g.ip" (hf_ua3g_ip) : sous-commande du message UA3G opcode 0x13
    # "IP Device Routing" envoyé par le système (System -> Terminal,
    # case SC_IP_DEVICE_ROUTING). Champ distinct de "ua3g.ip.cs" ci-dessous
    # (sens opposé) : jamais besoin de déduire le sens par le port.
    0x00: "Reset",
    0x01: "Start RTP",
    0x02: "Stop RTP",
    0x03: "Redirect",
    0x04: "Tone Definition",
    0x05: "Start Tone",
    0x06: "Stop Tone",
    0x07: "Start Listen RTP",
    0x08: "Stop Listen RTP",
    0x09: "Get Parameters Value",
    0x0A: "Set Parameters Value",
    0x0B: "Send Digit",
    0x0C: "Pause RTP",
    0x0D: "Restart RTP",
    0x0E: "Start Record RTP",
    0x0F: "Stop Record RTP",
    0x10: "Set SIP Parameters",
    0x11: "Free Seating",
    0x14: "Application Parameters",
}

UA3G_IP_DEVICE_ROUTING_CS_NAMES: dict[int, str] = {
    # str_command_cs_ip_device_routing[] (packet-ua3g.c), champ tshark
    # "ua3g.ip.cs" (hf_ua3g_ip_cs) : sous-commande du message UA3G opcode
    # 0x13 "IP Device Routing" envoyé par le terminal (Terminal -> System,
    # case CS_IP_DEVICE_ROUTING).
    0x00: "Init",
    0x01: "Incident",
    0x02: "Get Parameters Value Response",
    0x03: "QOS Ticket RSP",
}

UA3G_IP_DEVICE_ROUTING_PARAMETER_NAMES: dict[int, str] = {
    # ip_device_routing_cmd_get_param_req_vals[] (packet-ua3g.c) : identifie
    # un paramètre poste, partagée par deux champs tshark distincts qui
    # portent chacun une LISTE d'identifiants (un poste peut demander/
    # renvoyer plusieurs paramètres dans un seul message) :
    #   - "ua3g.ip.get_param_req.parameter" (hf_ua3g_ip_device_routing_
    #     get_param_req_parameter) : requête système, sous-commande 0x09
    #     "Get Parameters Value" (champ System->Terminal "ip" == 0x09).
    #   - "ua3g.ip.cs.cmd02.parameter" (hf_ua3g_cs_ip_device_routing_
    #     cmd02_parameter) : réponse terminal, sous-commande 0x02 "Get
    #     Parameters Value Response" (champ Terminal->System "ip_cs" ==
    #     0x02) — chaque identifiant y est dissecté DEUX FOIS de suite (une
    #     fois via l'item récapitulatif "%s" formaté, une fois via l'octet
    #     brut sous-jacent, toutes deux sur le même hf), d'où des valeurs
    #     dupliquées consécutivement côté tshark -T ek (ex: [3, 3, 4, 4]) —
    #     pas un artefact du normaliseur de ce projet, vérifié directement
    #     dans packet-ua3g.c (deux appels successifs à proto_tree_add_*
    #     sur le même champ). Non observé côté requête (un seul appel par
    #     paramètre dans le dissecteur), voir CHANGELOG pour le détail.
    # Note : ne couvre PAS "ua3g.ip.set_param_req.parameter" (sous-commande
    # 0x0A "Set Parameters Value") — voir
    # UA3G_IP_DEVICE_ROUTING_SET_PARAMETER_NAMES ci-dessous, table dédiée et
    # distincte côté dissecteur.
    0x00: "Firmware Version",
    0x01: "Firmware Version",
    0x02: "DHCP IP Address",
    0x03: "Local IP Address",
    0x04: "Subnetwork Mask",
    0x05: "Router IP Address",
    0x06: "TFTP IP Address",
    0x07: "MainCPU IP Address",
    0x08: "Default Codec",
    0x09: "Ethernet Drivers Config",
    0x0A: "MAC Address",
    0x0B: "Pseudo MAC Address",
}

UA3G_IP_DEVICE_ROUTING_SET_PARAMETER_NAMES: dict[int, str] = {
    # ip_device_routing_cmd_set_param_req_vals[]/..._vals_ext
    # (packet-ua3g.c) : identifie un paramètre poste pour le champ tshark
    # "ua3g.ip.set_param_req.parameter" (hf_ua3g_ip_device_routing_
    # set_param_req_parameter) — requête système, sous-commande 0x0A
    # "Set Parameters Value" (champ System->Terminal "ip" == 0x0A). Table
    # distincte de UA3G_IP_DEVICE_ROUTING_PARAMETER_NAMES ci-dessus malgré
    # la proximité du nom de champ tshark — aucune valeur des deux tables
    # à fusionner. 40 entrées comptées programmatiquement sur le source
    # (roadmap.md citait "~41", une estimation approximative antérieure au
    # comptage exact).
    # Comme "ua3g.ip.cs.cmd02.parameter" ci-dessus, ce champ porte une
    # LISTE d'identifiants ET chaque élément y est dissecté DEUX FOIS de
    # suite sur le même hf (proto_tree_add_uint_format puis
    # proto_tree_add_item, packet-ua3g.c lignes ~1577/1582) — mais cette
    # fois côté REQUÊTE système, pas réponse terminal : le doublement
    # dépend du champ précis dans le code du dissecteur, pas du sens du
    # message comme le laissait supposer le seul cas observé en session 33.
    # Vérifié à la fois dans le code source et sur les fixtures réelles
    # (ua3g_freeseating_ipv4/ipv6.ek.ndjson, ex: liste brute
    # [3, 3, 4, 4, 5, 5] pour un message ip=10 "Set Parameters Value").
    0x00: "QOS IP TOS",
    0x01: "QOS 8021 VLID",
    0x02: "QOS 8021 PRI",
    0x03: "SNMP MIB2 SysContact",
    0x04: "SNMP MIB2 SysName",
    0x05: "SNMP MIB2 SysLocation",
    0x06: "Default Compressor",
    0x07: "Error String Net Down",
    0x08: "Error String Cable PB",
    0x09: "Error String Try Connect",
    0x0A: "Error String Connected",
    0x0B: "Error String Reset",
    0x0C: "Error String Duplicate IP Address",
    0x0D: "SNMP MIB Community",
    0x0E: "TFTP Backup Sec Mode",
    0x0F: "TFTP Backup IP Address",
    0x10: "Set MMI Password",
    0x11: "Set PC Port Status",
    0x12: "Record RTP Authorization",
    0x13: "Security Flags",
    0x14: "ARP Spoofing",
    0x15: "Session Param",
    0x16: "Stable Mode",
    0x17: "DTMF Level",
    0x18: "Keep Talking",
    0x19: "BT Radio",
    0x1A: "Transparent Reboot",
    0x1B: "Set Skin Identifier",
    0x1C: "Set Language Identifier",
    0x1D: "Set Dialpad Rotation",
    0x1E: "Set USB Boost Charging",
    0x1F: "Set SSH Password",
    0x20: "DHCP Survivability",
    0x21: "USB Devices",
    0x22: "ALS Device",
    0x23: "Busy Light",
    0x24: "Audio Environment",
    0x25: "EEE Configuration",
    0x26: "LLDP Configuration",
    0x30: "MD5 Authentication",
}

UA3G_IP_DEVICE_ROUTING_FREESEATING_PARAMETER_NAMES: dict[int, str] = {
    # ip_device_routing_cmd_freeseating_vals[] (packet-ua3g.c, table
    # VALS() simple — pas de variante "_ext") : identifie un paramètre pour
    # le champ tshark répété "ua3g.ip.freeseating.parameter" (hf_ua3g_ip_
    # device_routing_freeseating_parameter) — requête système, sous-
    # commande 0x11 "Free Seating" (champ System->Terminal "ip" == 0x11).
    # Seulement 4 entrées côté dissecteur (contre 40 pour la table
    # SET_PARAMETER_NAMES ci-dessus) — pas de confusion possible entre les
    # deux malgré la structure de dissection très proche (même motif de
    # boucle "proto_tree_add_uint_format" + "proto_tree_add_item").
    # Comme "ua3g.ip.set_param_req.parameter" ci-dessus, ce champ porte une
    # LISTE d'identifiants ET chaque élément y est dissecté DEUX FOIS de
    # suite sur le même hf — vérifié sur les fixtures réelles
    # (ua3g_freeseating_ipv4/ipv6.ek.ndjson : liste brute [0, 0, 1, 1] côté
    # ipv4 et [0, 0, 1, 1, 2, 2] côté ipv6, jamais un identifiant isolé).
    # Recoupement sémantique avec les champs frères présents dans les
    # mêmes messages (non résolus ici, mais alignés positionnellement) :
    # ipv4 porte un champ "*_mac" (6 octets, aligné sur l'identifiant 0x00
    # doublé) suivi d'un champ "*_ip" (4 octets, aligné sur 0x01 doublé) ;
    # ipv6 porte le même champ "*_mac" (identifiant 0x00) suivi de DEUX
    # adresses IPv6 (16 octets chacune, alignées sur 0x01 puis 0x02
    # doublés) — cohérent avec "Maincpu1"/"Maincpu2" comme deux adresses
    # réseau distinctes d'un même poste en freeseating, pas un doublon.
    0x00: "Pseudo MAC Address",
    0x01: "Maincpu1",
    0x02: "Maincpu2",
    0x03: "Restart application",
}


def decode_name(table: dict[int, str], value: int | str | None) -> str | None:
    """Résout ``value`` (int, ou str numérique décimale/hexadécimale) dans
    ``table``.

    Accepte aussi bien "128" (décimal — champs ``class``/``method``/``event``
    tels que rendus par tshark) que "0x15" (hexadécimal — champs
    ``server``/``property``/``objectid`` : le dissecteur ``packet-noe.c``
    les rend en hexadécimal préfixé côté tshark, contrairement aux champs
    ci-dessus). Sans ``base=0`` explicite, ``int("0x15")`` lève
    ``ValueError`` et ces deux champs ne se résolvaient jamais, alors même
    que ``NOE_SERVER_NAMES``/``NOE_PROPERTY_NAMES`` contenaient l'entrée
    correspondante (constaté par recoupement avec les captures d'exemple —
    voir docs/noe-ua3g-homer-mapping.md §6ter).

    Retourne None si ``value`` est absent, non numérique, ou sans
    correspondance dans la table — jamais de valeur inventée ("unknown
    (0x..)" reste la responsabilité de l'appelant s'il le souhaite).
    """
    logger.trace("decode_name() appelée")
    if value is None:
        logger.trace("decode_name() retourne | None (valeur absente)")
        return None
    try:
        key = int(value, 0) if isinstance(value, str) else int(value)
    except (TypeError, ValueError):
        logger.trace("decode_name() retourne | None (valeur non numérique)")
        return None
    nom = table.get(key)
    logger.trace("decode_name() retourne | {}", "résolu" if nom else "None")
    return nom


def decode_names(table: dict[int, str], value: Any) -> list[str | None] | None:
    """Comme ``decode_name``, mais pour un champ tshark **répété** — une
    liste de valeurs plutôt qu'une seule (ex: plusieurs identifiants de
    paramètre demandés/renvoyés dans un même message "IP Device Routing").

    Résout chaque élément indépendamment via ``decode_name`` et retourne
    la liste alignée (même longueur et même ordre que ``value`` — y
    compris les doublons éventuels, voir la note sur
    ``UA3G_IP_DEVICE_ROUTING_PARAMETER_NAMES``), avec ``None`` aux
    positions non résolvables plutôt que de les retirer : la position de
    chaque élément reste ainsi exploitable pour un recoupement avec un
    champ répété sœur (ex: une liste de longueurs/valeurs associée).
    Accepte aussi une valeur scalaire isolée (tshark n'encapsule pas
    toujours un champ répété présent une seule fois dans une liste — même
    remarque que ``pick()`` dans ``fields.py``), auquel cas le résultat
    est une liste à un seul élément.

    Retourne None — jamais une liste "à moitié vide" — si ``value`` est
    None ou si aucun élément n'est résolvable : même contrat que
    ``decode_name``, pas de nom inventé.
    """
    logger.trace("decode_names() appelée")
    if value is None:
        logger.trace("decode_names() retourne | None (valeur absente)")
        return None
    items = value if isinstance(value, list) else [value]
    resolved = [decode_name(table, item) for item in items]
    liste = resolved if any(name is not None for name in resolved) else None
    logger.trace("decode_names() retourne | {}", "liste alignée" if liste else "None")
    return liste
