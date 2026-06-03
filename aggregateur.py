#!/usr/bin/env python3

from collections import defaultdict
from traqueur import Traqueur

def _mac_est_randomise(mac: str) -> bool:
    try:
        return (int(mac.split(":")[0], 16) & 0x02) != 0
    except Exception:
        return False

def _auto_classifier(mac: str, mac_randomise: bool, frames: list,
                     n_deauth: int, n_probe: int, n_eapol: int, n_auth: int,
                     ssids: set, bssids_deauth: set) -> dict | None:
    """
    Classifie sans appel LLM les cas évidents.
    Retourne un dict analyse ou None si le LLM doit décider.
    """

    # --- Jamais intéressant ---
    # Wildcard probes ou probes ciblés depuis MAC randomisé, sans rien d'autre
    if mac_randomise and not n_deauth and not n_eapol and not n_auth:
        return {
            "interesting": False,
            "threat_level": "none",
            "category": "normal",
            "reason": "Probes depuis MAC randomisé — protection vie privée standard, aucune valeur tactique."
        }

    # --- Toujours intéressant (sans LLM) ---

    # Deauth broadcast : déconnexion de masse
    if "ff:ff:ff:ff:ff:ff" in bssids_deauth:
        level = "high" if n_deauth >= 5 else "medium"
        return {
            "interesting": True,
            "threat_level": level,
            "category": "deauth_attack",
            "reason": f"{n_deauth} deauthentification(s) broadcast en 30s — attaque de déconnexion de masse probable."
        }

    # Deauth ciblé répété : attaque sur un client spécifique
    if n_deauth >= 3:
        return {
            "interesting": True,
            "threat_level": "medium",
            "category": "deauth_attack",
            "reason": f"{n_deauth} deauthentifications ciblées en 30s — déconnexion forcée d'un client."
        }

    # EAPOL : handshake WPA capturé
    if n_eapol >= 2:
        return {
            "interesting": True,
            "threat_level": "medium",
            "category": "handshake",
            "reason": f"Handshake WPA complet capturé ({n_eapol} trames EAPOL) — clé de session exposée."
        }

    # MAC permanent scannant de nombreux réseaux : reconnaissance active
    if not mac_randomise and n_probe > 0 and len(ssids) >= 5:
        return {
            "interesting": True,
            "threat_level": "medium",
            "category": "surveillance",
            "reason": f"MAC permanent ({mac}) sonde {len(ssids)} réseaux distincts en 30s — cartographie WiFi active."
        }

    return None  # cas ambigu → LLM


def agreger(candidats: list, traqueur: Traqueur | None = None) -> list:
    """
    Regroupe les candidats par MAC source.
    Retourne une liste d'agrégats, chacun avec une description comportementale
    et éventuellement une classification automatique (sans LLM).
    """
    groupes = defaultdict(list)
    for c in candidats:
        mac = c["layers"].get("wlan.sa", ["?"])[0]
        groupes[mac].append(c)

    agregats = []
    for mac, frames in groupes.items():
        mac_randomise = _mac_est_randomise(mac)

        subtypes    = [f["layers"].get("wlan.fc.type_subtype", [""])[0] for f in frames]
        n_deauth    = subtypes.count("0x000c")
        n_probe     = subtypes.count("0x0004")
        n_auth      = subtypes.count("0x000b")
        n_assoc     = subtypes.count("0x0000") + subtypes.count("0x0001")
        n_eapol     = sum(1 for f in frames if "eapol.type" in f["layers"])

        ssids = set()
        for f in frames:
            s = f["layers"].get("wlan.ssid", [""])[0]
            if s and s not in ("", "<MISSING>"):
                ssids.add(s)

        bssids_deauth = set(
            f["layers"].get("wlan.da", [""])[0]
            for f in frames
            if f["layers"].get("wlan.fc.type_subtype", [""])[0] == "0x000c"
        )

        signals = []
        for f in frames:
            try:
                signals.append(int(f["layers"].get("radiotap.dbm_antsignal", ["-100"])[0]))
            except ValueError:
                pass

        # --- Description comportementale ---
        mac_label = f"{'MAC randomisé' if mac_randomise else 'MAC PERMANENT'}"
        parties = [f"Appareil {mac} ({mac_label}) — {len(frames)} trame(s) en 30s"]

        if n_deauth:
            broadcast = "ff:ff:ff:ff:ff:ff" in bssids_deauth
            parties.append(
                f"{n_deauth} Deauthentification(s) {'broadcast (déconnexion de masse)' if broadcast else 'ciblée(s)'}"
            )
        if n_probe:
            if ssids:
                parties.append(
                    f"{n_probe} Probe(s) vers {len(ssids)} SSID(s) précis : {', '.join(list(ssids)[:6])}"
                )
            else:
                parties.append(f"{n_probe} Probe(s) wildcard (aucun réseau précis recherché)")
        if n_eapol:
            parties.append(f"{n_eapol} trame(s) EAPOL (handshake WPA)")
        if n_auth:
            parties.append(f"{n_auth} Authentication(s) 802.11")
        if n_assoc:
            parties.append(f"{n_assoc} Association(s)")
        if signals:
            parties.append(f"Signal {min(signals)} à {max(signals)} dBm")

        description = ". ".join(parties) + "."

        # Enregistre la sighting dans le traqueur
        if traqueur is not None:
            traqueur.voir(mac, ssids, signals)
            eval_traqueur = traqueur.evaluer(mac)
        else:
            eval_traqueur = {"niveau": "ignorer", "raison": ""}

        auto = _auto_classifier(
            mac, mac_randomise, frames,
            n_deauth, n_probe, n_eapol, n_auth,
            ssids, bssids_deauth
        )

        # Pour les MACs randomisés sans classification automatique évidente :
        # le traqueur peut décider d'escalader au LLM si l'appareil est persistant
        if auto is not None and auto["interesting"] is False and mac_randomise:
            niveau = eval_traqueur["niveau"]
            if niveau == "llm":
                # Appareil persistant ou en reconnaissance : on l'escalade
                contexte = traqueur.contexte_llm(mac) if traqueur else ""
                description = f"{description} {contexte}".strip()
                auto = None  # laisse le LLM décider
            elif niveau == "surveiller":
                # Pas encore suspect mais on continue à surveiller
                auto = {
                    "interesting": False,
                    "threat_level": "none",
                    "category": "normal",
                    "reason": eval_traqueur["raison"],
                }

        agregats.append({
            "mac":          mac,
            "description":  description,
            "frames":       frames,
            "auto_class":   auto,
        })

    return agregats
