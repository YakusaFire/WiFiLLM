#!/usr/bin/env python3
# =============================================================================
#  prefilter.py — Filtre déterministe des trames 802.11 (sans LLM)
# =============================================================================
#  Rôle       : Lit un pcap via tshark et en extrait uniquement les trames
#               présentant un intérêt opérationnel :
#               - Probe Request / Association / Authentication / Deauth / Disassoc
#               - EAPOL (handshake WPA2 4-way)
#               - Beacons dont le score de sur-sécurisation atteint >= 3 points
#                 (WPA3, PMF, GCMP-256, SSID masqué, signal anormal…)
#               Pour chaque trame retenue, construit une description textuelle
#               enrichie (SSID décodé, MAC randomisé/permanent, type d'échange)
#               destinée à aggregateur.py puis au LLM.
#
#  Entrée     : chemin vers un fichier .pcap
#  Sortie     : liste de dicts {numero, description, layers}
#
#  Dépend de  : tshark (subprocess)
#  Appelé par : pipeline.py
# =============================================================================

import subprocess
import json

INTERESTING_SUBTYPES = {
    "0x0000",  # Association Request
    "0x0001",  # Association Response
    "0x0004",  # Probe Request
    "0x000a",  # Disassociation
    "0x000b",  # Authentication
    "0x000c",  # Deauthentication
}

SUBTYPE_NOMS = {
    "0x0000": "Association Request",
    "0x0001": "Association Response",
    "0x0004": "Probe Request",
    "0x0008": "Beacon",
    "0x000a": "Disassociation",
    "0x000b": "Authentication",
    "0x000c": "Deauthentication",
}

# AKM suites (Authentication Key Management)
AKM_NOMS = {
    "00-0f-ac-1":  "WPA2-Enterprise (EAP)",
    "00-0f-ac-2":  "WPA2-PSK",
    "00-0f-ac-4":  "FT-PSK",
    "00-0f-ac-6":  "PSK-SHA256",
    "00-0f-ac-8":  "WPA3-SAE",
    "00-0f-ac-18": "WPA3-SAE-EXT",
    "00-0f-ac-11": "WPA3-Enterprise",
    "00-0f-ac-12": "WPA3-Enterprise-192",
}

# Cipher suites
CIPHER_NOMS = {
    "00-0f-ac-2": "TKIP",
    "00-0f-ac-4": "CCMP-128 (AES)",
    "00-0f-ac-8": "GCMP-128",
    "00-0f-ac-9": "GCMP-256",
}

# Canaux DFS (5GHz, moins courants, nécessitent une configuration avancée)
CANAUX_DFS = {52, 56, 60, 64, 100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140}

def decoder_ssid(raw: str) -> str:
    if not raw or raw in ("(vide)", "<MISSING>"):
        return ""
    try:
        return bytes.fromhex(raw).decode("utf-8", errors="replace").strip("\x00")
    except ValueError:
        return raw

def lire_canal(layers: dict) -> str:
    """Canal radio d'un beacon : DS Parameter Set en priorité, sinon radiotap."""
    for champ in ("wlan.ds.current_channel", "wlan_radio.channel"):
        val = layers.get(champ, [""])
        if val and val[0] not in ("", "<MISSING>"):
            return str(val[0])
    return ""

def signal_dbm(layers: dict) -> int:
    """Signal radiotap en dBm (entier), -100 par défaut/illisible."""
    try:
        return int(layers.get("radiotap.dbm_antsignal", ["-100"])[0])
    except (ValueError, IndexError):
        return -100

def extraire_metadonnees(pcap_path: str) -> list:
    cmd = [
        "tshark", "-r", pcap_path, "-T", "json",
        "-e", "frame.number",
        "-e", "wlan.fc.type_subtype",
        "-e", "wlan.ssid",
        "-e", "wlan.bssid",
        "-e", "wlan.sa",
        "-e", "wlan.da",
        "-e", "radiotap.dbm_antsignal",
        "-e", "eapol.type",
        # Canal (DS Parameter Set du beacon, sinon dérivé du radiotap) —
        # discriminant evil_twin : un AP pirate est souvent sur un autre canal.
        "-e", "wlan.ds.current_channel",
        "-e", "wlan_radio.channel",
        # Sécurité beacon
        "-e", "wlan.rsn.akms",
        "-e", "wlan.rsn.pcs",
        "-e", "wlan.rsn.capabilities.mfpr",
        "-e", "wlan.rsn.capabilities.mfpc",
        "-e", "wlan.fixed.beacon",
    ]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
    if not result.stdout.strip():
        return []
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError:
        return []

def score_securite_beacon(layers: dict) -> tuple[int, list]:
    """
    Calcule un score de sécurité pour un beacon.
    Plus le score est élevé, plus le réseau est "sur-sécurisé" pour un civil.
    Retourne (score, liste des indices détectés).
    """
    score = 0
    indices = []

    ssid = decoder_ssid(layers.get("wlan.ssid", [""])[0])
    akms = layers.get("wlan.rsn.akms", [])
    ciphers = layers.get("wlan.rsn.pcs", [])
    mfpr = layers.get("wlan.rsn.capabilities.mfpr", ["0"])[0]
    mfpc = layers.get("wlan.rsn.capabilities.mfpc", ["0"])[0]
    signal = layers.get("radiotap.dbm_antsignal", ["0"])[0]
    beacon_interval = layers.get("wlan.fixed.beacon", ["100"])[0]

    try:
        intervalle = int(beacon_interval)
    except ValueError:
        intervalle = 100

    try:
        sig = int(signal)
    except ValueError:
        sig = -100

    # SSID masqué
    if not ssid or ssid == "":
        score += 2
        indices.append("SSID masqué")

    # WPA3-SAE
    akms_liste = akms if isinstance(akms, list) else [akms]
    for akm in akms_liste:
        nom = AKM_NOMS.get(str(akm).lower(), "")
        if "WPA3" in nom or "SAE" in nom:
            score += 3
            indices.append(f"Chiffrement {nom}")
        elif "Enterprise" in nom or "EAP" in nom:
            score += 2
            indices.append(f"Auth {nom}")

    # Cipher avancé (GCMP-256)
    ciphers_liste = ciphers if isinstance(ciphers, list) else [ciphers]
    for c in ciphers_liste:
        nom = CIPHER_NOMS.get(str(c).lower(), "")
        if "GCMP-256" in nom:
            score += 2
            indices.append("Chiffrement GCMP-256 (grade militaire)")
        elif "GCMP-128" in nom:
            score += 1
            indices.append("Chiffrement GCMP-128")

    # PMF Required (802.11w)
    if str(mfpr) in ("1", "true", "True"):
        score += 3
        indices.append("Protection des trames de gestion obligatoire (802.11w)")
    elif str(mfpc) in ("1", "true", "True"):
        score += 1
        indices.append("Protection des trames de gestion activée")

    # Signal anormalement fort en extérieur (antenne amplifiée probable)
    if sig > -25:
        score += 2
        indices.append(f"Signal extrêmement fort ({sig}dBm — antenne directionnelle probable)")

    # Beacon interval non standard
    if intervalle < 50 or intervalle > 200:
        score += 1
        indices.append(f"Intervalle beacon non standard ({intervalle} TU)")

    return score, indices

def est_interessant(frame: dict) -> bool:
    layers = frame.get("_source", {}).get("layers", {})

    if "eapol.type" in layers:
        return True

    subtype = layers.get("wlan.fc.type_subtype", [""])[0]

    if subtype == "0x0008":
        ssid = layers.get("wlan.ssid", [""])[0]
        # Réseau caché
        if ssid == "":
            return True
        # Beacon avec profil de sécurité suspect
        score, _ = score_securite_beacon(layers)
        return score >= 3

    return subtype in INTERESTING_SUBTYPES

def construire_description(frame: dict) -> str:
    layers = frame.get("_source", {}).get("layers", {})
    subtype = layers.get("wlan.fc.type_subtype", ["?"])[0]
    ssid = decoder_ssid(layers.get("wlan.ssid", [""])[0])
    bssid = layers.get("wlan.bssid", ["?"])[0]
    src = layers.get("wlan.sa", ["?"])[0]
    dst = layers.get("wlan.da", ["?"])[0]
    signal = layers.get("radiotap.dbm_antsignal", ["?"])[0]
    eapol = layers.get("eapol.type", [None])[0]
    nom_type = SUBTYPE_NOMS.get(subtype, subtype)

    if eapol is not None:
        return f"Trame EAPOL (protocole d'authentification WPA2) échangée entre {src} et l'AP {bssid} — handshake 4-way en cours, signal {signal}dBm"

    if subtype == "0x000c":
        broadcast = dst == "ff:ff:ff:ff:ff:ff"
        cible = "tous les clients (broadcast)" if broadcast else f"le client {dst}"
        return f"Deauthentication envoyée par {src} vers {cible}, BSSID {bssid}, signal {signal}dBm"

    if subtype == "0x000a":
        return f"Disassociation depuis {src} vers {dst}, AP {bssid}, signal {signal}dBm"

    if subtype == "0x0004":
        mac_randomise = (int(src.split(":")[0], 16) & 0x02) != 0 if src != "?" else False
        mac_info = " (MAC randomisé)" if mac_randomise else " (MAC permanent)"
        if ssid:
            ssid_txt = f"le réseau connu '{ssid}' (probe ciblé — révèle l'historique réseau)"
        else:
            ssid_txt = "n'importe quel réseau (wildcard probe)"
        return f"Probe Request depuis {src}{mac_info} cherchant {ssid_txt}, signal {signal}dBm"

    if subtype == "0x0008":
        score, indices = score_securite_beacon(layers)
        ssid_txt = f"'{ssid}'" if ssid and ssid != "(vide)" else "MASQUÉ"
        canal = lire_canal(layers)
        canal_txt = f", canal {canal}" if canal else ""
        desc = f"Beacon réseau {ssid_txt}, BSSID {bssid}{canal_txt}, signal {signal}dBm"
        if indices:
            desc += f". Profil de sécurité : {', '.join(indices)}"
            desc += f". Score de sur-sécurisation : {score}/12 — un civil ordinaire n'activerait pas ces protections simultanément"
        return desc

    if subtype in ("0x0000", "0x0001"):
        return f"{nom_type} entre {src} et l'AP {bssid}, signal {signal}dBm"

    if subtype == "0x000b":
        return f"Authentication entre {src} et {bssid}, signal {signal}dBm"

    return f"Trame {nom_type} depuis {src} vers {dst}, AP {bssid}, signal {signal}dBm"

def filtrer_pcap(pcap_path: str) -> list:
    frames = extraire_metadonnees(pcap_path)
    candidats = []
    beacons_par_bssid: dict = {}   # bssid -> (signal, candidat)
    for frame in frames:
        layers = frame.get("_source", {}).get("layers", {})
        subtype = layers.get("wlan.fc.type_subtype", [""])[0]

        if subtype == "0x0008":
            # TOUS les beacons sont inventoriés (ils alimentent le registre AP
            # pour la détection d'evil twin), mais DÉDUPLIQUÉS par BSSID : on ne
            # garde que la trame au signal le plus fort, pour ne pas inonder le
            # pipeline avec les ~15 beacons/AP d'une fenêtre de 30 s.
            bssid = layers.get("wlan.bssid", ["?"])[0]
            sig = signal_dbm(layers)
            prev = beacons_par_bssid.get(bssid)
            if prev is None or sig > prev[0]:
                beacons_par_bssid[bssid] = (sig, {
                    "numero": layers.get("frame.number", ["?"])[0],
                    "ssid": decoder_ssid(layers.get("wlan.ssid", [""])[0]),
                    "description": construire_description(frame),
                    "layers": layers,
                })
        elif est_interessant(frame):
            candidats.append({
                "numero": layers.get("frame.number", ["?"])[0],
                "ssid": decoder_ssid(layers.get("wlan.ssid", [""])[0]),
                "description": construire_description(frame),
                "layers": layers,
            })

    candidats.extend(cand for _, cand in beacons_par_bssid.values())
    return candidats
