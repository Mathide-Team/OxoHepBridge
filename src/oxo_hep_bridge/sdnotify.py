#!/usr/bin/env python3
"""Notification systemd (sd_notify) : READY=1, WATCHDOG=1, STOPPING=1.

`systemctl status` ne sait pas, par défaut, distinguer un pont qui tourne
normalement d'un pont dont le thread de lecture tshark s'est bloqué en
silence (process vivant, mais qui ne traite plus aucun paquet) : le service
reste marqué actif indéfiniment. Le protocole `sd_notify` de systemd résout
ce problème par un canal de communication minimal, indépendant de
`STDOUT`/`STDERR` : un datagramme texte envoyé sur une socket Unix dont le
chemin est donné par la variable d'environnement `NOTIFY_SOCKET`.

Implémenté ici sans dépendance à `libsystemd` ni au paquet PyPI
`sdnotify` — seul `socket.AF_UNIX` (bibliothèque standard) est nécessaire,
dans le même esprit que le reste du projet (aucune dépendance lourde). Deux
briques :

- `SdNotifier` : envoie les messages (`READY=1`, `STOPPING=1`, `WATCHDOG=1`,
  `STATUS=...`). No-op silencieux si `NOTIFY_SOCKET` n'est pas définie (hors
  service systemd, ou `Type=simple` sans `Type=notify`) — permet à `cli.py`
  d'appeler `ready()`/`stopping()` inconditionnellement sans avoir à tester
  à chaque fois si le process tourne sous systemd.
- `WatchdogScheduler` : envoie `WATCHDOG=1` périodiquement sur un thread
  daemon (même style que `KeepaliveScheduler`), à la moitié de l'intervalle
  annoncé par systemd (`WATCHDOG_USEC`, dérivé de `WatchdogSec=` dans
  l'unité) — marge de sécurité recommandée par la documentation sd_notify
  pour tolérer un cycle ponctuellement plus lent sans déclencher de
  redémarrage intempestif. No-op si `WatchdogSec=` n'est pas configuré côté
  unité systemd (comportement historique inchangé, comme pour le keepalive
  HEP et son intervalle nul).

Portée volontairement limitée : cette notification est un timer indépendant
du thread principal, pas un heartbeat asservi à la progression réelle de la
boucle de lecture/envoi (`Bridge.run()`). Elle détecte donc un process
totalement figé (interpréteur bloqué, deadlock complet) ou disparu, mais PAS
un appel réseau individuellement bloqué (ex: `send()` TCP qui ne revient
jamais parce que le collecteur cesse de lire sans fermer la connexion) tant
que le reste du process continue de tourner. Documenté explicitement plutôt
que présenté comme une détection de blocage complète — même esprit que
l'avertissement sur `--hep-compress-payload` (voir docs/hep-chunks.md).
"""

from __future__ import annotations

import os
import socket
import threading

from loguru import logger

from oxo_hep_bridge.i18n import _


class SdNotifier:
    """Client sd_notify minimal.

    `socket_path` par défaut à la valeur de `NOTIFY_SOCKET` au moment de la
    construction (comportement standard) ; un chemin explicite peut être
    injecté pour les tests, sans dépendre de `os.environ`.
    """

    def __init__(self, socket_path: str | None = None) -> None:
        self.socket_path = (
            socket_path if socket_path is not None else os.environ.get("NOTIFY_SOCKET")
        )

    @property
    def enabled(self) -> bool:
        return bool(self.socket_path)

    def _send(self, message: str) -> bool:
        if not self.socket_path:
            return False
        addr = self.socket_path
        # Espace de noms abstrait Linux : convention systemd/socket Unix, le
        # chemin est alors préfixé par '@' plutôt que par un octet nul brut
        # (illisible/non transmissible tel quel dans une variable d'env).
        if addr.startswith("@"):
            addr = "\0" + addr[1:]
        try:
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
            try:
                sock.connect(addr)
                sock.sendall(message.encode("utf-8"))
            finally:
                sock.close()
        except OSError as exc:
            logger.warning(_("échec d'envoi de la notification sd_notify {!r} : {}"), message, exc)
            return False
        return True

    def ready(self) -> bool:
        """Signale à systemd que le démarrage est terminé (`Type=notify`)."""
        return self._send("READY=1")

    def stopping(self) -> bool:
        """Signale un arrêt volontaire en cours (évite un faux `failed`)."""
        return self._send("STOPPING=1")

    def watchdog(self) -> bool:
        """Ping de vie périodique, attendu par systemd sous `WatchdogSec=`."""
        return self._send("WATCHDOG=1")

    def status(self, text: str) -> bool:
        """Message libre visible dans `systemctl status` (best-effort)."""
        return self._send(f"STATUS={text}")


def resolve_watchdog_interval(env: os._Environ[str] | dict[str, str] | None = None) -> float | None:
    """Lit `WATCHDOG_USEC`/`WATCHDOG_PID` et retourne l'intervalle watchdog
    (en secondes), ou `None` si le watchdog n'est pas actif pour ce process.

    `None` dans trois cas, tous silencieux (pas de watchdog = comportement
    historique, comme pour `keepalive_interval = 0`) :
    - `WATCHDOG_USEC` absent (`WatchdogSec=` non configuré côté unité
      systemd) ou non numérique ;
    - valeur <= 0 ;
    - `WATCHDOG_PID` présent et différent du PID courant — cas d'un
      sous-process qui hériterait de l'environnement sans être le process
      réellement surveillé par systemd ; vérification recommandée par la
      documentation `sd_notify(3)`.
    """
    source = env if env is not None else os.environ
    raw = source.get("WATCHDOG_USEC")
    if not raw:
        return None
    pid_raw = source.get("WATCHDOG_PID")
    if pid_raw and pid_raw.isdigit() and int(pid_raw) != os.getpid():
        return None
    try:
        usec = int(raw)
    except ValueError:
        return None
    if usec <= 0:
        return None
    return usec / 1_000_000


class WatchdogScheduler:
    """Envoie `WATCHDOG=1` toutes les `watchdog_interval / 2` secondes sur un
    thread daemon, jusqu'à `stop()`.

    `watchdog_interval` à `None` ou <= 0 désactive le mécanisme : `start()`
    devient un no-op (même contrat que `KeepaliveScheduler` avec
    `interval <= 0`), ce qui évite à l'appelant (`cli.py`) de devoir tester
    la valeur avant d'appeler `start()`/`stop()`.
    """

    def __init__(self, notifier: SdNotifier, watchdog_interval: float | None) -> None:
        self.notifier = notifier
        self.watchdog_interval = watchdog_interval
        self._notify_every = (
            watchdog_interval / 2 if watchdog_interval and watchdog_interval > 0 else None
        )
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None
        self.sent_count = 0

    @property
    def enabled(self) -> bool:
        return self.notifier.enabled and self._notify_every is not None and self._notify_every > 0

    def _run(self) -> None:
        if self._notify_every is None:
            # Invariant garanti par enabled/start() ci-dessus : _run() n'est
            # jamais lancé sur un thread avec _notify_every à None. Exception
            # explicite plutôt qu'un assert (supprimé sous python -O) pour
            # satisfaire le narrowing mypy sans dépendre d'un mécanisme
            # désactivable à l'exécution.
            raise RuntimeError(
                _("_notify_every ne devrait jamais être None ici (voir enabled/start())")
            )
        while not self._stop_event.wait(self._notify_every):
            if self.notifier.watchdog():
                self.sent_count += 1
                logger.debug("watchdog systemd notifié (#{})", self.sent_count)

    def start(self) -> None:
        if not self.enabled or self._thread is not None:
            return
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._run, name="oxo-hep-watchdog", daemon=True)
        self._thread.start()
        logger.debug(
            "watchdog systemd démarré (WATCHDOG_USEC={}s, notification toutes les {}s)",
            self.watchdog_interval,
            self._notify_every,
        )

    def stop(self, *, timeout: float = 5.0) -> None:
        if self._thread is None:
            return
        self._stop_event.set()
        self._thread.join(timeout=timeout)
        self._thread = None
