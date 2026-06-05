#!/usr/bin/env python3

import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from prefilter import est_interessant, construire_description

VERT = "\033[92m"
ROUGE = "\033[91m"
JAUNE = "\033[93m"
RESET = "\033[0m"
GRAS = "\033[1m"

def frame(numero, subtype, ssid="", bssid="AA:BB:CC:DD:EE:FF",
          src="11:22:33:44:55:66", dst="FF:FF:FF:FF:FF:FF",
          signal="-65", eapol=None):
    layers = {
        "frame.number": [str(numero)],
        "wlan.fc.type_subtype": [subtype],
        "wlan.ssid": [ssid],
        "wlan.bssid": [bssid],
        "wlan.sa": [src],
        "wlan.da": [dst],
        "radiotap.dbm_antsignal": [signal],
    }
    if eapol is not None:
        layers["eapol.type"] = [str(eapol)]
    return {"_source": {"layers": layers}}

TRAMES = [
    # ─── BANALES — doivent être ignorées ──────────────────────────────────────
    (frame(1,  "0x0008", ssid="SFR_1234",    signal="-82"), False, "Beacon SFR_1234 (voisin, signal faible)"),
    (frame(2,  "0x0008", ssid="Livebox-AB12",signal="-78"), False, "Beacon Livebox voisin"),
    (frame(3,  "0x0008", ssid="FreeWifi",    signal="-75"), False, "Beacon FreeWifi public"),
    (frame(4,  "0x0008", ssid="bbox-ABCD",   signal="-80"), False, "Beacon bbox"),
    (frame(5,  "0x0029", signal="-60"),                     False, "ACK / trame de contrôle"),
    (frame(6,  "0x0028", signal="-55"),                     False, "Null data (keepalive)"),
    (frame(7,  "0x0020", ssid="",            signal="-70"), False, "Data chiffrée ordinaire"),

    # ─── INTÉRESSANTES — doivent passer ──────────────────────────────────────
    (frame(8,  "0x000c", ssid="",            signal="-38",
           dst="FF:FF:FF:FF:FF:FF"),                        True,  "Deauth broadcast (possible attaque)"),
    (frame(9,  "0x000c", ssid="",            signal="-45",
           dst="CC:DD:EE:FF:00:11"),                        True,  "Deauth ciblé vers un client"),
    (frame(10, "0x000a", signal="-50"),                     True,  "Disassociation"),
    (frame(11, "0x0004", ssid="MonBureau_WiFi", signal="-55"), True, "Probe Request SSID connu"),
    (frame(12, "0x0004", ssid="AirFrance_Wifi", signal="-60"), True, "Probe Request réseau public connu"),
    (frame(13, "0x0000", signal="-48"),                     True,  "Association Request"),
    (frame(14, "0x0001", signal="-48"),                     True,  "Association Response"),
    (frame(15, "0x000b", signal="-52"),                     True,  "Authentication (début handshake)"),
    (frame(16, "0x0008", ssid="",            signal="-20"), True,  "Beacon réseau caché (SSID vide)"),
    (frame(17, "0x0008", ssid="",            signal="-15"), True,  "Beacon réseau caché signal très fort"),
    (frame(18, "0x0000", signal="-48"),      eapol := None, True,  ""),  # sera écrasé
    (frame(19, "data",   signal="-62",       eapol=1),      True,  "EAPOL — handshake WPA2"),
    (frame(20, "data",   signal="-58",       eapol=2),      True,  "EAPOL — message 2/4 du 4-way handshake"),
]

# Correction ligne 18 (mal construite ci-dessus, on la remplace)
TRAMES[17] = (frame(18, "data", signal="-62", eapol=1), True, "EAPOL — handshake WPA2 message 1/4")

def run():
    print(f"\n{GRAS}{'─'*70}{RESET}")
    print(f"{GRAS}  TEST DU PRÉ-FILTRE — {len(TRAMES)} trames{RESET}")
    print(f"{GRAS}{'─'*70}{RESET}\n")

    ok = 0
    echecs = []

    for i, (f, attendu, label) in enumerate(TRAMES, 1):
        resultat = est_interessant(f)
        correct = resultat == attendu

        if correct:
            ok += 1
            statut = f"{VERT}✓{RESET}"
        else:
            echecs.append((i, label, attendu, resultat))
            statut = f"{ROUGE}✗{RESET}"

        tag = f"{VERT}GARDÉ   {RESET}" if resultat else f"{JAUNE}IGNORÉ  {RESET}"
        print(f"  {statut} #{i:02d} [{tag}] {label}")

        if resultat:
            desc = construire_description(f)
            print(f"         {GRAS}→{RESET} {desc}")

    print(f"\n{GRAS}{'─'*70}{RESET}")
    print(f"  Résultat : {ok}/{len(TRAMES)} correct(s)", end="")

    if echecs:
        print(f"  {ROUGE}— {len(echecs)} échec(s){RESET}")
        print(f"\n  {ROUGE}Problèmes :{RESET}")
        for num, label, attendu, obtenu in echecs:
            attendu_txt = "GARDÉ" if attendu else "IGNORÉ"
            obtenu_txt  = "GARDÉ" if obtenu  else "IGNORÉ"
            print(f"    #{num:02d} {label}")
            print(f"        attendu={attendu_txt}  obtenu={obtenu_txt}")
    else:
        print(f"  {VERT}— tous corrects ✓{RESET}")

    print(f"{GRAS}{'─'*70}{RESET}\n")

if __name__ == "__main__":
    run()
