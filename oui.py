#!/usr/bin/env python3
# =============================================================================
#  oui.py — Résolution OUI → fabricant à partir de la base manuf de Wireshark
# =============================================================================
#  Rôle       : Donne le fabricant d'une adresse MAC à partir de son OUI (les
#               3 premiers octets, attribués par l'IEEE). Lookup 100 %
#               déterministe contre la base `manuf` livrée avec Wireshark/tshark
#               — JAMAIS demandé au LLM (qui hallucinerait les marques).
#               Ne résout QUE les MAC permanentes : une MAC randomisée
#               (bit 0x02 du 1er octet) a un OUI bidon → retourne None.
#
#  Entrée     : fabricant(mac: str)  — ex. "94:83:c4:a9:34:bb"
#  Sortie     : nom du fabricant (str) ou None (randomisée / inconnue / base absente)
#
#  Dépend de  : /usr/share/wireshark/manuf (présent dès que tshark est installé)
#  Appelé par : aggregateur.py
# =============================================================================

import os

_MANUF_PATHS = [
    "/usr/share/wireshark/manuf",
    "/usr/share/tshark/manuf",
    "/usr/share/wireshark/wka",
]

_cache = None  # dict {OUI 'XX:XX:XX' majuscule -> nom fabricant}

# Le capteur opère TOUJOURS en posture "terrain" (déposé en zone, passif) : il n'y
# a plus de mode "calibration". Tout matériel d'infrastructure domestique repéré
# en zone est, par principe, potentiellement adverse → suspect.

# Fabricants de matériel "maison" / d'infrastructure domestique (box, routeurs
# portables). En zone opérationnelle, leur présence est anormale → suspecte.
# NB : un deauth/handshake émis par ces équipements reste de toute façon détecté
# par les règles déterministes de aggregateur.py.
FABRICANTS_SITE = (
    "GL Technologies",   # GL.iNet — routeurs portables
    "Sagemcom",          # box internet
)

# Fabricants de matériel typiquement utilisé comme OUTIL D'ATTAQUE WiFi, quel que
# soit le mode : un module ESP8266/ESP32 (Espressif) qui sonde ou deauth est, dans
# le modèle de menace du projet, un deauther/outil d'attaque bon marché. Verdict
# déterministe (le petit LLM hallucinait une catégorie hors-contrat "module_iot"
# → retombait bénin : faux négatif, cf. rapport_benchmark_v1 P3).
FABRICANTS_OUTILS = (
    "Espressif",         # ESP8266/ESP32 — deauthers, firmwares d'attaque répandus
)


def _charger() -> dict:
    global _cache
    if _cache is not None:
        return _cache
    _cache = {}
    chemin = next((p for p in _MANUF_PATHS if os.path.exists(p)), None)
    if not chemin:
        return _cache
    try:
        with open(chemin, encoding="utf-8", errors="ignore") as f:
            for ligne in f:
                ligne = ligne.rstrip("\n")
                if not ligne or ligne.startswith("#"):
                    continue
                parts = ligne.split("\t")
                oui = parts[0]
                # On ne garde que les OUI sur 24 bits ('XX:XX:XX').
                # Les attributions MA-M/MA-S ('XX:XX:XX:X0/28', '/36') sont ignorées.
                if len(oui) != 8 or "/" in oui:
                    continue
                # Colonne 3 = nom complet ("Espressif Inc."), sinon colonne 2 (court).
                nom = parts[2] if len(parts) >= 3 and parts[2] else (
                    parts[1] if len(parts) >= 2 else "")
                if nom:
                    _cache[oui.upper()] = nom
    except OSError:
        pass
    return _cache


def mac_randomise(mac: str) -> bool:
    try:
        return (int(mac.split(":")[0], 16) & 0x02) != 0
    except (ValueError, IndexError):
        return False


def fabricant(mac: str) -> str | None:
    """Fabricant d'une MAC permanente, ou None (randomisée / inconnue / base absente)."""
    if not mac or mac in ("?", "ff:ff:ff:ff:ff:ff") or mac_randomise(mac):
        return None
    oui = ":".join(mac.split(":")[:3]).upper()
    return _charger().get(oui)


def _fab_dans(mac: str, liste) -> bool:
    fab = fabricant(mac)
    return bool(fab) and any(k.lower() in fab.lower() for k in liste)


def materiel_suspect(mac: str) -> bool:
    """Matériel d'infrastructure domestique (box, routeur portable) repéré en zone
    → suspect (le capteur opère toujours en posture terrain)."""
    return _fab_dans(mac, FABRICANTS_SITE)


def materiel_offensif(mac: str) -> bool:
    """Matériel typiquement offensif (ESP deauther…), toujours suspect."""
    return _fab_dans(mac, FABRICANTS_OUTILS)
