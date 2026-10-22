#!/usr/bin/env python3
"""Compteurs d'exécution et journalisation de synthèse de fin de run.

Statistiques minimales et testables — Pas de dépendance externe autre que
loguru (déjà utilisée par le reste du projet). Le but est d'avoir un récapitulatif
complet et lisible à la fin de chaque exécution, sans surcharger la journalisation
en cours de run.
"""

from __future__ import annotations

from dataclasses import dataclass

from loguru import logger


@dataclass
class Stats:
    """Compteurs cumulés sur un run du pont oxo-hep-bridge.

    - ``received`` : nombre de paquets lus depuis la source tshark -T ek
    - ``normalized`` : nombre de paquets transformés avec succès en HepPacket
    - ``skipped`` : nombre de paquets sans donnée UA exploitable (bruit réseau
      capturé par erreur, filtrage normal de normalize())
    - ``sent`` : nombre de paquets HEP effectivement envoyés au collecteur
    - ``send_errors`` : nombre d'erreurs réseau à l'envoi (ex : collecteur
      injoignable, socket UDP saturé) — un paquet qui échoue puis réussit
      grâce à ``--hep-retries`` n'est PAS compté ici, uniquement l'échec
      définitif après épuisement des tentatives
    - ``send_retries`` : nombre cumulé de tentatives d'envoi supplémentaires
      effectivement consommées sur tout le run (``--hep-retries``/
      ``--hep-retry-backoff``) — 0 si le retry est désactivé (défaut) ou si
      le sender n'a jamais eu besoin de retenter
    - ``tshark_errors`` : nombre d'erreurs fatales remontées par tshark
      (paquet tronqué, capture illisible, etc.)
    - ``normalize_errors`` : nombre de paquets qui ont déclenché une exception
      non gérée pendant normalize() — ne devrait normalement pas arriver,
      signale un bug potentiel
    """

    received: int = 0
    normalized: int = 0
    skipped: int = 0
    sent: int = 0
    send_errors: int = 0
    send_retries: int = 0
    tshark_errors: int = 0
    normalize_errors: int = 0

    @property
    def success_rate(self) -> float:
        """Pourcentage de paquets reçus effectivement envoyés au collecteur."""
        logger.trace("success_rate() appelée")
        if self.received == 0:
            logger.trace("success_rate() retourne | 0.0 (aucun paquet)")
            return 0.0
        taux = (self.sent / self.received) * 100.0
        logger.trace("success_rate() retourne | {:.1f}%", taux)
        return taux

    def log_summary(self, *, verbose: bool = False) -> None:
        """Affiche le récapitulatif de fin de run via loguru.

        Affiche toujours les compteurs principaux (reçus, envoyés, ignorés,
        erreurs). Si ``verbose=True`` ou si des erreurs non nulles sont
        détectées, affiche aussi le détail des erreurs (send_errors,
        normalize_errors, tshark_errors).

        Chaque enregistrement est en plus lié (``logger.bind()``) au dict
        complet retourné par ``to_dict()``, sous la clé ``stats`` — invisible
        dans la sortie texte humaine habituelle (stderr), mais exploité par
        un éventuel sink JSON (``--log-json-file``, voir cli.py) : ce dernier
        y retrouve alors la totalité des compteurs sous
        ``record.extra.stats``, pas seulement les quelques valeurs
        interpolées dans le message texte.
        """
        logger.trace("log_summary() appelée | verbose={}", verbose)
        data = self.to_dict()
        logger.bind(stats=data).info(
            "terminé : {} paquets reçus, {} envoyés, {} ignorés ({} envoyés/reçus)",
            self.received,
            self.sent,
            self.skipped,
            f"{self.success_rate:.1f}%",
        )
        has_errors = self.send_errors or self.normalize_errors or self.tshark_errors
        if verbose or has_errors or self.send_retries:
            logger.bind(stats=data).info(
                "détail — erreurs d'envoi : {}, tentatives d'envoi supplémentaires : {}, "
                "erreurs normalize() : {}, erreurs fatales tshark : {}",
                self.send_errors,
                self.send_retries,
                self.normalize_errors,
                self.tshark_errors,
            )
        logger.trace("log_summary() retourne | récapitulatif émis")

    def to_dict(self) -> dict[str, int | float]:
        """Sérialisation en dict des compteurs cumulés.

        Consommé par `log_summary()` (lié à chaque enregistrement de fin de
        run/progression via `logger.bind(stats=...)`, exploité par un sink
        JSON `--log-json-file` s'il est configuré, voir cli.py) et testé
        directement ici pour son propre compte (JSON-sérialisable, round-trip
        des compteurs)."""
        return {
            "received": self.received,
            "normalized": self.normalized,
            "skipped": self.skipped,
            "sent": self.sent,
            "send_errors": self.send_errors,
            "send_retries": self.send_retries,
            "normalize_errors": self.normalize_errors,
            "tshark_errors": self.tshark_errors,
            "success_rate": round(self.success_rate, 2),
        }
