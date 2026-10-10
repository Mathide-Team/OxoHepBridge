#!/usr/bin/env python3
"""Source de paquets décodés via tshark -T ek (Elasticsearch Bulk NDJSON).

Pas de pyshark, pas de scapy : on invoque directement le binaire tshark en
subprocess et on parse sa sortie NDJSON ligne par ligne.

Particularités réelles du format -T ek (vérifiées sur captures officielles) :
  - chaque paquet produit DEUX lignes :
      1. une ligne d'action   {"index":{"_index":"packets-..."}}
      2. une ligne document   {"timestamp":"...","layers":{...}}
  - les noms de champs sont doublement préfixés : "uaudp.opcode" →
    "uaudp_uaudp_opcode" (protocole + champ).
  - les valeurs sont souvent des listes ; un paquet peut porter plusieurs
    messages NOE empilés dans "ua":{"noe":[ {...}, {...} ]}.
  - champs absents par paquet → tolérance.
"""

from __future__ import annotations

import json
import subprocess
import threading
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from loguru import logger

from oxo_hep_bridge.i18n import _


class TsharkError(RuntimeError):
    """Levée quand le subprocess tshark se termine en erreur (code non nul)."""


def parse_ek_line(line: str) -> dict[str, Any] | None:
    """Parse une ligne NDJSON de tshark -T ek.

    Retourne le dict `layers` du paquet, ou None pour les lignes d'action
    d'index ({"index":{...}}) ou les lignes vides/malformées.
    """
    line = line.strip()
    if not line:
        return None
    try:
        obj = json.loads(line)
    except json.JSONDecodeError:
        logger.warning(_("Ligne non-JSON ignorée : {!r}"), line[:80])
        return None
    if not isinstance(obj, dict):
        return None
    # ligne d'action bulk → on l'ignore
    if "index" in obj and "layers" not in obj:
        return None
    layers = obj.get("layers")
    if not isinstance(layers, dict):
        return None
    return layers


def flatten_layers(layers: dict[str, Any]) -> dict[str, Any]:
    """Aplatit le dict `layers` de tshark -T ek en {champ: scalaire|liste}.

    Les valeurs sont laissées telles quelles (listes ou scalaires) ; le
    normaliseur saura extraire le premier élément via pick().
    """
    flat: dict[str, Any] = {}
    for fields in layers.values():
        if not isinstance(fields, dict):
            continue
        for key, val in fields.items():
            if key == "text":
                continue
            flat[key] = val
    return flat


class TsharkEKSource:
    """Wrap un subprocess tshark -T ek et expose iter_packets()."""

    def __init__(
        self,
        *,
        tshark_path: str = "tshark",
        interface: str | None = None,
        pcap: str | Path | None = None,
        bpf: str | None = None,
        fields: list[str] | None = None,
        decode_as: list[str] | None = None,
        line_buffered: bool = True,
    ) -> None:
        if not interface and not pcap:
            raise ValueError(_("interface ou pcap requis"))
        self.tshark_path = tshark_path
        self.interface = interface
        self.pcap = str(pcap) if pcap else None
        self.bpf = bpf
        self.fields = fields or []
        self.decode_as = decode_as or []
        self.line_buffered = line_buffered

    def _build_cmd(self) -> list[str]:
        cmd = [self.tshark_path, "-T", "ek"]
        if self.line_buffered:
            cmd.append("-l")
        if self.pcap:
            cmd += ["-r", self.pcap]
        elif self.interface:
            cmd += ["-i", self.interface]
        if self.bpf:
            cmd += ["-f", self.bpf]
        for da in self.decode_as:
            cmd += ["-d", da]
        for f in self.fields:
            cmd += ["-e", f]
        return cmd

    def iter_packets(self) -> Iterator[dict[str, Any]]:
        """Itère sur les paquets décodés (dict layers aplati).

        En cas d'interruption (Ctrl-C, GeneratorExit lors d'un `break` côté
        appelant), le subprocess tshark est arrêté proprement : `terminate()`
        puis, s'il ne répond pas sous 5 s, `kill()`. Si le processus se
        termine avec un code d'erreur alors qu'on ne l'a pas nous-même arrêté,
        `TsharkError` est levée pour signaler une panne réelle plutôt que de
        continuer silencieusement.
        """
        cmd = self._build_cmd()
        logger.debug("lancement tshark : {}", " ".join(cmd))
        proc = subprocess.Popen(  # noqa: S603
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
        )
        # drainer stderr en arrière-plan pour éviter deadlock
        stderr_lines: list[str] = []

        def _drain_stderr() -> None:
            if proc.stderr is None:
                # Invariant garanti par Popen(stderr=subprocess.PIPE)
                # ci-dessus. Exception explicite plutôt qu'un assert
                # (supprimé sous python -O), même choix que pour
                # proc.stdout ci-dessous et pour WatchdogScheduler._run()
                # dans sdnotify.py.
                raise RuntimeError(_("proc.stderr est None malgré stderr=PIPE"))
            for raw in proc.stderr:
                stderr_lines.append(raw.rstrip())

        t = threading.Thread(target=_drain_stderr, daemon=True)
        t.start()

        if proc.stdout is None:
            raise RuntimeError(_("proc.stdout est None malgré stdout=PIPE"))
        we_interrupted = False
        try:
            for line in proc.stdout:
                layers = parse_ek_line(line)
                if layers is not None:
                    yield flatten_layers(layers)
        except (GeneratorExit, KeyboardInterrupt):
            we_interrupted = True
            raise
        finally:
            proc.stdout.close()
            # tshark finit normalement tout seul après avoir lu toutes les
            # lignes de stdout. On attend d'abord un retour propre ; seulement
            # s'il ne se termine pas sous 5 s (ex: capture live en cours,
            # ou interruption) on force l'arrêt via terminate() puis kill().
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                logger.warning(_("tshark ne se termine pas, envoi de terminate()"))
                proc.terminate()
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    logger.warning(_("tshark ne répond pas à terminate(), envoi de kill()"))
                    proc.kill()
                    proc.wait(timeout=5)
            t.join(timeout=5)
            rc = proc.returncode
            if stderr_lines:
                for msg in stderr_lines[-5:]:
                    logger.warning(_("tshark stderr : {}"), msg)
            if rc not in (0, None) and not we_interrupted:
                raise TsharkError(_("tshark s'est terminé avec le code {rc}").format(rc=rc))
