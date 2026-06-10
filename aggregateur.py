#!/usr/bin/env python3
# =============================================================================
#  aggregateur.py — Agrégation comportementale par MAC + classification auto
# =============================================================================
#  Rôle       : Regroupe les candidats (issus de prefilter.py) par adresse MAC
#               source, puis tente de classer chaque appareil sans appeler le LLM.
#               Les cas évidents sont résolus immédiatement (règles déterministes) :
#               - Wildcard probes depuis MAC randomisé → ignoré (vie privée civile)
#               - Deauth broadcast ou >= 3 deauth ciblées  → deauth_attack
#               - >= 2 trames EAPOL                        → handshake
#               - MAC permanent sondant >= 5 SSID          → surveillance
#               Pour les cas ambigus, une description comportementale synthétique
#               (types de trames, SSIDs sondés, signal, historique traqueur) est
#               construite et renvoyée pour soumission au LLM.
#               Le Traqueur peut escalader un MAC randomisé persistant au LLM.
#
#  Entrée     : liste de candidats {numero, description, layers}  +  Traqueur
#  Sortie     : liste d'agrégats {mac, description, frames, auto_class}
#               auto_class = dict analyse si classifié, None si LLM requis
#
#  Dépend de  : traqueur.py
#  Appelé par : pipeline.py
# =============================================================================

from collections import defaultdict
from traqueur import Traqueur
from registre_ap import RegistreAP
from oui import fabricant, materiel_suspect, materiel_offensif
from prefilter import score_securite_beacon, decoder_ssid, lire_canal

def _mac_est_randomise(mac: str) -> bool:
    try:
        return (int(mac.split(":")[0], 16) & 0x02) != 0
    except Exception:
        return False

def _mac_avec_fabricant(mac: str) -> str:
    """'AA:BB:CC:… (Fabricant)' si l'OUI est résolu (MAC permanente connue),
    sinon la MAC seule. Permet d'enrichir TOUTES les MAC d'une trame suspecte
    (source, cible de deauth, BSSID) et pas seulement l'émetteur."""
    fab = fabricant(mac)
    return f"{mac} ({fab})" if fab else mac

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

    # Matériel typiquement offensif (ESP deauther) en activité (sonde/auth/assoc).
    # Les deauth/handshake sont déjà tranchés plus haut ; ici on attrape le cas
    # ESP-qui-sonde, que le LLM ratait en hallucinant une catégorie "module_iot"
    # hors-contrat → faux négatif (cf. rapport_benchmark_v1 P3). Verdict déterministe.
    if materiel_offensif(mac) and (n_probe or n_auth):
        return {
            "interesting": True,
            "threat_level": "medium",
            "category": "surveillance",
            "reason": f"Matériel typiquement offensif ({fabricant(mac)}) en sondage actif "
                      f"({n_probe} probe(s)) — deauther/outil d'attaque bon marché probable."
        }

    return None  # cas ambigu → LLM


def agreger(candidats: list, traqueur: Traqueur | None = None,
            registre: RegistreAP | None = None) -> list:
    """
    Regroupe les candidats par MAC source.
    Retourne une liste d'agrégats, chacun avec une description comportementale
    et éventuellement une classification automatique (sans LLM).

    Si un `registre` (RegistreAP) est fourni, chaque beacon alimente la carte
    persistante SSID→BSSID ; un nouveau BSSID usurpant un SSID déjà connu
    (statut "conflit") est escaladé au LLM avec une comparaison des AP, qui
    tranche l'evil_twin par antériorité.
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
        n_beacon    = subtypes.count("0x0008")

        # Profil de sécurité du beacon le plus "sur-sécurisé" (réutilise prefilter).
        # Sans ça, un AP furtif/over-secured arrivait au LLM sans aucun indice.
        beacon_score, beacon_indices, beacon_masque, canal = 0, [], False, ""
        for f in frames:
            if f["layers"].get("wlan.fc.type_subtype", [""])[0] == "0x0008":
                sc, ind = score_securite_beacon(f["layers"])
                if sc >= beacon_score:
                    beacon_score, beacon_indices = sc, ind
                if f["layers"].get("wlan.ssid", [""])[0] in ("", "<MISSING>"):
                    beacon_masque = True
                if not canal:
                    canal = lire_canal(f["layers"])

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

        # OUI des AUTRES MAC d'une trame suspecte (pas seulement l'émetteur) :
        #  - cible d'une deauth ciblée (wlan.da) = la VICTIME ; sa MAC n'est pas
        #    spoofée → son fabricant révèle QUEL appareil est attaqué.
        #  - BSSID (wlan.bssid) = l'AP concerné/usurpé ; ≠ source pour une deauth/
        #    EAPOL/auth (pour un beacon, bssid == sa, déjà couvert par la source).
        cibles_deauth = {b for b in bssids_deauth if b not in ("ff:ff:ff:ff:ff:ff", "")}
        bssids_ap = {
            f["layers"].get("wlan.bssid", [""])[0] for f in frames
        } - {"ff:ff:ff:ff:ff:ff", "", "?", mac}

        signals = []
        for f in frames:
            try:
                signals.append(int(f["layers"].get("radiotap.dbm_antsignal", ["-100"])[0]))
            except ValueError:
                pass

        # --- Description comportementale ---
        mac_label = f"{'MAC randomisé' if mac_randomise else 'MAC PERMANENT'}"
        # Fabricant via OUI (3 premiers octets) — uniquement pour les MAC permanentes.
        fab = fabricant(mac)
        if not fab:
            fab_txt = ""
        elif materiel_suspect(mac):
            fab_txt = f", fabricant: {fab} [matériel d'infrastructure domestique — suspect en zone opérationnelle]"
        else:
            fab_txt = f", fabricant: {fab}"
        parties = [f"Appareil {mac} ({mac_label}{fab_txt}) — {len(frames)} trame(s) en 30s"]

        if n_deauth:
            broadcast = "ff:ff:ff:ff:ff:ff" in bssids_deauth
            if broadcast:
                parties.append(f"{n_deauth} Deauthentification(s) broadcast (déconnexion de masse)")
            else:
                cibles_txt = ", ".join(_mac_avec_fabricant(c) for c in sorted(cibles_deauth)[:4])
                parties.append(
                    f"{n_deauth} Deauthentification(s) ciblée(s)"
                    + (f" vers {cibles_txt}" if cibles_txt else "")
                )
        if n_probe:
            if ssids:
                parties.append(
                    f"{n_probe} Probe(s) vers {len(ssids)} SSID(s) précis : "
                    f"{', '.join(decoder_ssid(s) for s in list(ssids)[:6])}"
                )
            else:
                parties.append(f"{n_probe} Probe(s) wildcard (aucun réseau précis recherché)")
        if n_eapol:
            parties.append(f"{n_eapol} trame(s) EAPOL (handshake WPA)")
        if n_auth:
            parties.append(f"{n_auth} Authentication(s) 802.11")
        if n_assoc:
            parties.append(f"{n_assoc} Association(s)")
        if n_beacon:
            nom_ssid = "SSID MASQUÉ" if beacon_masque else (decoder_ssid(list(ssids)[0]) if ssids else "SSID inconnu")
            if beacon_indices:
                parties.append(
                    f"Beacon AP ({nom_ssid}) — profil de sécurité : {', '.join(beacon_indices)} "
                    f"(score sur-sécurisation {beacon_score}/12)"
                )
            else:
                parties.append(f"Beacon AP ({nom_ssid})")
        # Fabricant de l'AP concerné (BSSID), quand il diffère de la source et que
        # son OUI est résolu — éclaire deauth/EAPOL/auth visant ou usurpant un AP.
        ap_txt = ", ".join(sorted(_mac_avec_fabricant(b) for b in bssids_ap if fabricant(b)))
        if ap_txt:
            parties.append(f"AP concerné : {ap_txt}")
        if signals:
            parties.append(f"Signal {min(signals)} à {max(signals)} dBm")

        description = ". ".join(parties) + "."

        # --- Registre persistant des AP (détection evil_twin) ---
        # Un beacon = un AP ; sa MAC source EST le BSSID. On enregistre tout AP
        # à SSID visible pour bâtir la carte SSID→BSSID dans la durée et obtenir
        # le statut : "conflit" = ce SSID, déjà connu, est soudain annoncé par
        # un nouveau BSSID (signature evil_twin).
        statut_registre = None
        ssid_ap = decoder_ssid(next(iter(ssids), "")) if n_beacon else ""
        if registre is not None and ssid_ap:
            statut_registre = registre.observer(ssid_ap, mac, {
                "vendor":      fab,
                "canal":       canal,
                "profil_secu": (", ".join(beacon_indices) if beacon_indices
                                else "profil civil (WPA2/ouvert)"),
                "score_secu":  beacon_score,
                "signal_max":  max(signals) if signals else -100,
            })

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

        # --- Verdicts AP : evil_twin (LLM) puis mesh (déterministe) ---
        # 1) evil_twin : un NOUVEAU BSSID usurpe un SSID déjà connu (vendor/sécurité
        #    typiquement DIFFÉRENTS) → escalade avec la COMPARAISON des AP, le LLM
        #    désigne l'imposteur. Prime sur tout le reste (attaque en cours).
        # 2) mesh : un même SSID porté par ≥2 BSSID du MÊME fabricant (kit mesh /
        #    multi-AP). Inhabituel en zone → suspect, verdict DÉTERMINISTE (pas de
        #    LLM). Distinct de l'evil_twin par le critère "même vendor".
        escalade_evil_twin = (statut_registre == "conflit")
        infos_mesh = (registre.infos_mesh(ssid_ap)
                      if (registre is not None and ssid_ap) else None)

        # MESH d'abord : si ≥2 BSSID du MÊME fabricant portent ce SSID, c'est un
        # mesh/multi-AP, pas un evil twin (lequel a un vendor différent). Le
        # registre marque pourtant le 2e BSSID "conflit" (il ignore le vendor) ;
        # on tranche donc le mesh AVANT l'escalade evil_twin pour ne pas l'envoyer
        # à tort au LLM. Un vrai evil twin (vendor différent) → infos_mesh=None →
        # retombe sur l'escalade ci-dessous.
        if n_beacon and infos_mesh is not None and (auto is None or not auto["interesting"]):
            canaux = ", ".join(infos_mesh["canaux"])
            auto = {
                "interesting": True,
                "threat_level": "medium",
                "category": "mesh",
                "reason": (f"Réseau mesh détecté : '{ssid_ap}' annoncé par "
                           f"{infos_mesh['n_bssid']} BSSID du même fabricant "
                           f"({infos_mesh['vendor']}, canal/aux {canaux}) — infrastructure "
                           f"multi-AP inhabituelle en zone, probablement adverse."),
            }

        elif escalade_evil_twin:
            comparaison = registre.description_comparative(ssid_ap)
            description = f"{description} {comparaison}".strip()
            auto = None

        # Beacon ordinaire (1 seul BSSID, ni sur-sécurisé, ni conflit, ni mesh) :
        # classé bénin de façon déterministe pour ne pas inonder le LLM.
        elif n_beacon and auto is None and not (beacon_masque or beacon_score >= 3):
            auto = {
                "interesting": False,
                "threat_level": "none",
                "category": "normal",
                "reason": "Beacon AP ordinaire — enregistré au registre, aucun conflit de SSID.",
            }

        agregats.append({
            "mac":          mac,
            "description":  description,
            "frames":       frames,
            "auto_class":   auto,
        })

    return agregats
