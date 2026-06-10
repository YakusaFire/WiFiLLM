#!/usr/bin/env python3
# =============================================================================
#  registre_ap.py — Mémoire PERSISTANTE des points d'accès (carte SSID → BSSID)
# =============================================================================
#  Rôle       : Maintient sur DISQUE (horizon jours/semaines) la liste des AP
#               vus pour chaque SSID. C'est le pendant persistant du Traqueur
#               (qui, lui, oublie en RAM après 10 min) et la brique qui rend
#               possible la détection d'EVIL TWIN : un même SSID annoncé par
#               plusieurs BSSID distincts.
#
#               Principe — l'ANTÉRIORITÉ fait la légitimité : le BSSID vu en
#               premier / le plus souvent est la référence présumée ; un BSSID
#               qui apparaît ensuite sur ce SSID établi est un « nouveau venu »
#               suspect. Le registre ne JUGE pas (pas de verdict hostile) : il
#               détecte le CONFLIT et produit une description comparative des
#               AP en présence (antériorité, vendor OUI, sécurité, canal,
#               signal). C'est le LLM, en aval, qui désigne l'imposteur.
#
#  Entrée     : observer(ssid, bssid, infos) depuis aggregateur.py
#               (infos = {vendor, canal, profil_secu, score_secu, signal_max})
#  Sortie     : observer(...) -> statut ∈ {"ignore","premier_du_ssid","connu","conflit"}
#               description_comparative(ssid) -> texte injecté dans le prompt LLM
#
#  Persistance: /data/capture/registre_ap.json  (écriture atomique)
#  Appelé par : aggregateur.py (via pipeline.py qui instancie le RegistreAP)
# =============================================================================

import os
import json
import time

REGISTRE_PATH = "/data/capture/registre_ap.json"

# Un BSSID est encore considéré « nouveau venu » (donc susceptible de lever un
# conflit evil_twin) tant qu'il n'a pas été vu sur plus de N fenêtres. Au-delà,
# il fait partie du décor connu du SSID → on ne ré-escalade plus (anti-bruit).
SEUIL_ALERTE_FENETRES = 2
# Au-delà de cette inactivité, un BSSID est oublié (un AP légitime déplacé ne
# doit pas rester une « référence » éternelle).
MAX_AGE_JOURS = 14


def _humaniser_age(secondes: float) -> str:
    s = int(secondes)
    if s < 60:
        return "moins d'1 min"
    if s < 3600:
        return f"{s // 60} min"
    if s < 86400:
        return f"{s // 3600} h"
    j = s // 86400
    h = (s % 86400) // 3600
    return f"{j} j {h} h" if h else f"{j} j"


class RegistreAP:
    """
    Carte persistante SSID → {BSSID → infos}. Détecte qu'un SSID est annoncé
    par plusieurs BSSID (signature evil_twin) et fournit la comparaison au LLM.
    """

    def __init__(self, chemin: str = REGISTRE_PATH):
        self._chemin = chemin
        self._aps: dict[str, dict] = {}   # {ssid: {bssid: entrée}}
        self._fenetre = 0                 # compteur de fenêtre (1 par pcap)
        self.charger()

    # ------------------------------------------------------------------ cycle
    def nouvelle_fenetre(self) -> None:
        """À appeler une fois par pcap, avant les observations de la fenêtre."""
        self._fenetre += 1

    def observer(self, ssid: str, bssid: str, infos: dict) -> str:
        """
        Enregistre/actualise un AP (SSID + BSSID) et retourne le statut :
          "ignore"          — SSID masqué/vide (non indexable)
          "premier_du_ssid" — seul BSSID connu pour ce SSID
          "connu"           — BSSID déjà établi, rien de neuf
          "conflit"         — ce SSID a ≥2 BSSID et CE bssid est un nouveau venu
                              (récent) → à soumettre au LLM (evil twin possible)
        """
        if not ssid or not bssid or bssid in ("?", "ff:ff:ff:ff:ff:ff"):
            return "ignore"

        aps = self._aps.setdefault(ssid, {})
        now = time.time()

        if bssid not in aps:
            aps[bssid] = {
                "premiere_vue":     now,
                "derniere_vue":     now,
                "derniere_fenetre": self._fenetre,
                "n_fenetres":       1,
                "vendor":           infos.get("vendor"),
                "canal":            infos.get("canal"),
                "profil_secu":      infos.get("profil_secu", ""),
                "score_secu":       infos.get("score_secu", 0),
                "signal_max":       infos.get("signal_max", -100),
            }
        else:
            e = aps[bssid]
            e["derniere_vue"] = now
            # n_fenetres compte des FENÊTRES distinctes, pas des beacons : robuste
            # même si plusieurs beacons d'un BSSID arrivent dans le même pcap.
            if e.get("derniere_fenetre") != self._fenetre:
                e["n_fenetres"] += 1
                e["derniere_fenetre"] = self._fenetre
            if infos.get("signal_max") is not None:
                e["signal_max"] = max(e.get("signal_max", -100), infos["signal_max"])
            for k in ("vendor", "canal", "profil_secu", "score_secu"):
                v = infos.get(k)
                if v not in (None, "", 0):
                    e[k] = v

        autres = [b for b in aps if b != bssid]
        if not autres:
            return "premier_du_ssid"
        if aps[bssid]["n_fenetres"] <= SEUIL_ALERTE_FENETRES:
            return "conflit"
        return "connu"

    # ------------------------------------------------------------- description
    def description_comparative(self, ssid: str) -> str:
        """
        Construit la phrase comparative à injecter dans le prompt LLM : tous les
        BSSID du SSID, du plus ancien (référence) au plus récent, avec leurs
        caractéristiques discriminantes. Vide si moins de 2 BSSID.
        """
        aps = self._aps.get(ssid, {})
        if len(aps) < 2:
            return ""

        # Le plus ANCIEN d'abord (premiere_vue croissante) = référence présumée.
        items = sorted(aps.items(), key=lambda kv: kv[1]["premiere_vue"])
        ref_bssid = items[0][0]
        now = time.time()

        lignes = [
            f"[COMPARAISON evil-twin POSSIBLE — SSID '{ssid}' annoncé par "
            f"{len(aps)} BSSID distincts]"
        ]
        for bssid, e in items:
            vendor = e.get("vendor") or "fabricant inconnu (OUI non attribué)"
            secu   = e.get("profil_secu") or "profil de sécurité non lu"
            canal  = e.get("canal") or "?"
            sig    = e.get("signal_max", -100)
            anc    = _humaniser_age(now - e["premiere_vue"])
            if bssid == ref_bssid:
                marq = " [ANTÉRIEUR — référence légitime présumée]"
            elif e["n_fenetres"] <= SEUIL_ALERTE_FENETRES:
                marq = " [NOUVEAU VENU]"
            else:
                marq = ""
            lignes.append(
                f"- BSSID {bssid} ({vendor}) : vu {e['n_fenetres']}× sur {anc}, "
                f"canal {canal}, {secu}, signal max {sig} dBm.{marq}"
            )
        lignes.append(
            "Le BSSID le plus ancien / le plus souvent vu est la référence "
            "légitime ; un nouveau venu au signal plus fort, à la sécurité plus "
            "faible (downgrade), au fabricant (OUI) ou au canal différents est un "
            "evil twin probable — désigne-le."
        )
        return " ".join(lignes)

    # -------------------------------------------------------------- mesh
    def infos_mesh(self, ssid: str) -> dict | None:
        """
        Détecte un réseau MESH / multi-AP : un même SSID annoncé par ≥2 BSSID
        partageant le MÊME fabricant (kit mesh grand public ou infrastructure :
        Eero, Orbi, Deco, AP d'entreprise…). C'est la signature qui DISTINGUE le
        mesh de l'evil twin (lequel a typiquement un vendor/sécurité DIFFÉRENTS).

        En posture terrain, un réseau mesh est inhabituel donc suspect.

        Retourne {vendor, n_bssid, bssids, canaux} si mesh détecté, sinon None.
        """
        aps = self._aps.get(ssid, {})
        if len(aps) < 2:
            return None
        # Regroupe les BSSID par fabricant (OUI résolu, non vide).
        par_vendor: dict[str, list] = {}
        for bssid, e in aps.items():
            v = e.get("vendor")
            if v:
                par_vendor.setdefault(v, []).append(bssid)
        for vendor, bssids in par_vendor.items():
            if len(bssids) >= 2:
                canaux = sorted({str(aps[b].get("canal") or "?") for b in bssids})
                return {
                    "vendor":  vendor,
                    "n_bssid": len(bssids),
                    "bssids":  sorted(bssids),
                    "canaux":  canaux,
                }
        return None

    # -------------------------------------------------------------- entretien
    def purger(self, max_age_jours: int = MAX_AGE_JOURS) -> None:
        """Oublie les BSSID inactifs depuis > max_age_jours, puis les SSID vidés."""
        limite = max_age_jours * 86400
        now = time.time()
        for ssid in list(self._aps):
            for bssid in list(self._aps[ssid]):
                if now - self._aps[ssid][bssid].get("derniere_vue", now) > limite:
                    del self._aps[ssid][bssid]
            if not self._aps[ssid]:
                del self._aps[ssid]

    # ------------------------------------------------------------------- I/O
    def charger(self) -> None:
        try:
            with open(self._chemin, encoding="utf-8") as f:
                data = json.load(f)
            self._aps = data.get("aps", {}) if isinstance(data, dict) else {}
        except (FileNotFoundError, json.JSONDecodeError, OSError):
            self._aps = {}
        # Compteur de fenêtre monotone à travers les redémarrages : on repart
        # au-dessus de la plus grande fenêtre déjà mémorisée.
        maxf = 0
        for bssids in self._aps.values():
            for e in bssids.values():
                maxf = max(maxf, e.get("derniere_fenetre", 0))
        self._fenetre = maxf

    def sauver(self) -> None:
        d = os.path.dirname(self._chemin)
        try:
            if d:
                os.makedirs(d, exist_ok=True)
            tmp = self._chemin + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump({"aps": self._aps}, f, ensure_ascii=False, indent=2)
            os.replace(tmp, self._chemin)  # écriture atomique
        except OSError:
            pass

    # --------------------------------------------------------------- accès test
    def ssids(self) -> list:
        return list(self._aps)

    def bssids(self, ssid: str) -> list:
        return list(self._aps.get(ssid, {}))
