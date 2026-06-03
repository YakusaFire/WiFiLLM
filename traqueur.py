#!/usr/bin/env python3

import time
from collections import defaultdict

# Un appareil devient suspect si on le revoit dans plusieurs captures successives
SEUIL_PERSISTANCE    = 4    # apparitions dans des fenêtres distinctes
SEUIL_SSID_DIVERSITE = 5    # nombre de SSID distincts sondés (reconnaissance active)
FENETRE_OUBLI        = 600  # secondes — on oublie un appareil après 10 min sans activité


class Traqueur:
    """
    Maintient l'historique inter-pcap des appareils observés.
    Permet de distinguer un passant (vu 1 fois) d'un appareil persistant (ennemi potentiel).
    """

    def __init__(self):
        self._historique: dict[str, dict] = {}

    def voir(self, mac: str, ssids: set, signals: list) -> None:
        now = time.time()
        if mac not in self._historique:
            self._historique[mac] = {
                "premiere_vue":    now,
                "derniere_vue":    now,
                "n_apparitions":   1,
                "ssids_cumules":   set(ssids),
                "signaux":         list(signals),
            }
        else:
            h = self._historique[mac]
            h["derniere_vue"]   = now
            h["n_apparitions"] += 1
            h["ssids_cumules"]  |= ssids
            h["signaux"].extend(signals)
            h["signaux"] = h["signaux"][-50:]  # garde les 50 dernières valeurs

    def nettoyer(self) -> None:
        now = time.time()
        expirés = [m for m, h in self._historique.items()
                   if now - h["derniere_vue"] > FENETRE_OUBLI]
        for m in expirés:
            del self._historique[m]

    def evaluer(self, mac: str) -> dict:
        """
        Retourne un dict avec le niveau de suspicion de cet appareil.

        Niveaux :
          "ignorer"   — passant normal, aucune valeur
          "surveiller" — légèrement persistant, à garder en œil
          "llm"       — comportement anormal, soumettre au LLM
        """
        h = self._historique.get(mac)
        if h is None:
            return {"niveau": "ignorer", "raison": "première apparition"}

        n        = h["n_apparitions"]
        n_ssids  = len(h["ssids_cumules"])
        duree    = h["derniere_vue"] - h["premiere_vue"]  # secondes

        # Reconnaissance active : sonde beaucoup de réseaux distincts
        if n_ssids >= SEUIL_SSID_DIVERSITE:
            return {
                "niveau": "llm",
                "raison": (
                    f"Appareil vu {n}× en {int(duree)}s, "
                    f"a sondé {n_ssids} SSID distincts — cartographie WiFi active."
                ),
            }

        # Persistance : reste dans la zone au-delà du passage normal
        if n >= SEUIL_PERSISTANCE:
            signaux = h["signaux"]
            sig_txt = ""
            if signaux:
                sig_min, sig_max = min(signaux), max(signaux)
                variation = sig_max - sig_min
                sig_txt = (
                    f" Signal {sig_min}→{sig_max} dBm "
                    f"({'stable — appareil stationnaire probable' if variation <= 10 else 'variable'})"
                )
            return {
                "niveau": "llm",
                "raison": (
                    f"Appareil vu {n}× sur {int(duree)}s ({int(duree/60)}min).{sig_txt}"
                ),
            }

        # Légèrement persistant : trop tôt pour conclure
        if n >= 2:
            return {"niveau": "surveiller", "raison": f"Vu {n}× — surveillance en cours"}

        return {"niveau": "ignorer", "raison": "première apparition, comportement normal"}

    def contexte_llm(self, mac: str) -> str:
        """
        Construit la phrase de contexte historique à ajouter à la description LLM.
        """
        h = self._historique.get(mac)
        if h is None:
            return ""
        n       = h["n_apparitions"]
        n_ssids = len(h["ssids_cumules"])
        duree   = int(h["derniere_vue"] - h["premiere_vue"])
        ssids_str = ", ".join(list(h["ssids_cumules"])[:8]) if h["ssids_cumules"] else "aucun"
        return (
            f"[HISTORIQUE : présent {n}× sur les {duree}s écoulées, "
            f"{n_ssids} SSID(s) distincts sondés au total : {ssids_str}]"
        )
