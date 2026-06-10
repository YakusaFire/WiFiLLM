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

# MODE D'EMPLOI DU CAPTEUR (variable d'env CAPTEUR_MODE) :
#   "calibration" — au bureau/atelier : le matériel maison (GL.iNet, box…) est
#                   ATTENDU → traité comme bénin (évite les faux positifs).
#   "terrain"     — capteur déposé en zone, passif : ce MÊME matériel n'a rien
#                   à faire là → devient potentiellement HOSTILE → suspect.
MODE = os.environ.get("CAPTEUR_MODE", "calibration").lower()

# Fabricants du matériel "maison" / d'infrastructure de référence.
# En calibration : bénins. En terrain : suspects (matériel adverse probable).
# NB : dans les deux cas, un deauth/handshake émis par ces équipements reste
# détecté par les règles déterministes de aggregateur.py — ce switch ne joue
# que sur le jugement "mou" du LLM.
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


def infra_connue(mac: str) -> bool:
    """Équipement maison ATTENDU (bénin) — seulement en mode calibration."""
    return MODE == "calibration" and _fab_dans(mac, FABRICANTS_SITE)


def materiel_suspect_zone(mac: str) -> bool:
    """Matériel maison repéré EN ZONE (suspect) — seulement en mode terrain."""
    return MODE == "terrain" and _fab_dans(mac, FABRICANTS_SITE)


def materiel_offensif(mac: str) -> bool:
    """Matériel typiquement offensif (ESP deauther…), suspect dans TOUS les modes."""
    return _fab_dans(mac, FABRICANTS_OUTILS)
