#!/usr/bin/env python3

from prefilter import est_interessant, construire_description, score_securite_beacon

VERT  = "\033[92m"
ROUGE = "\033[91m"
JAUNE = "\033[93m"
BLEU  = "\033[94m"
RESET = "\033[0m"
GRAS  = "\033[1m"

def beacon(numero, ssid, bssid="AA:BB:CC:DD:EE:FF", signal="-65",
           akms=None, ciphers=None, mfpr="0", mfpc="0", canal="6", intervalle="100"):
    layers = {
        "frame.number":                     [str(numero)],
        "wlan.fc.type_subtype":             ["0x0008"],
        "wlan.ssid":                        [ssid],
        "wlan.bssid":                       [bssid],
        "wlan.sa":                          [bssid],
        "wlan.da":                          ["ff:ff:ff:ff:ff:ff"],
        "radiotap.dbm_antsignal":           [signal],
        "wlan.rsn.akms":                    akms or [],
        "wlan.rsn.pcs":                     ciphers or [],
        "wlan.rsn.capabilities.mfpr":       [mfpr],
        "wlan.rsn.capabilities.mfpc":       [mfpc],
        "wlan_mgt.ds.current_channel":      [canal],
        "wlan.beacon_interval":             [intervalle],
    }
    return {"_source": {"layers": layers}}

SCENARIOS = [
    # ─── CIVILS NORMAUX — doivent être ignorés ────────────────────────────────
    (beacon(1, "SFR_1234",     akms=["00-0f-ac-2"], ciphers=["00-0f-ac-4"], signal="-80"),
     False, "Box SFR standard — WPA2-PSK, CCMP, SSID visible"),

    (beacon(2, "Livebox-AB12", akms=["00-0f-ac-2"], ciphers=["00-0f-ac-4"], signal="-75"),
     False, "Livebox Orange — WPA2-PSK, CCMP, SSID visible"),

    (beacon(3, "bbox-ABCD",    akms=["00-0f-ac-2"], ciphers=["00-0f-ac-4"], signal="-70"),
     False, "Bbox Bouygues — WPA2-PSK, CCMP, SSID visible"),

    (beacon(4, "MonWiFi",      akms=["00-0f-ac-2"], ciphers=["00-0f-ac-4"],
            mfpc="1", signal="-65"),
     False, "Routeur avec WPA2 + PMF capable (pas obligatoire) — limite acceptable"),

    # ─── SUSPECTS — doivent être détectés ────────────────────────────────────
    (beacon(5, "",             akms=["00-0f-ac-8"], ciphers=["00-0f-ac-4"],
            mfpr="1", signal="-30"),
     True, "SSID caché + WPA3-SAE + PMF obligatoire + signal fort — profil opérationnel"),

    (beacon(6, "ResidentielX", akms=["00-0f-ac-8"], ciphers=["00-0f-ac-9"],
            mfpr="1", signal="-45"),
     True, "WPA3-SAE + GCMP-256 + PMF obligatoire — chiffrement grade militaire"),

    (beacon(7, "",             akms=["00-0f-ac-12"], ciphers=["00-0f-ac-9"],
            mfpr="1", canal="120", signal="-35"),
     True, "SSID caché + WPA3-Enterprise-192 + GCMP-256 + PMF + canal DFS — très suspect"),

    (beacon(8, "",             akms=["00-0f-ac-8"], ciphers=["00-0f-ac-4"],
            mfpr="1", signal="-18"),
     True, "SSID caché + WPA3 + PMF + signal extrême -18dBm (antenne directionnelle)"),

    (beacon(9, "FreePublic",   akms=["00-0f-ac-8"], ciphers=["00-0f-ac-9"],
            mfpr="1", canal="112", intervalle="20"),
     True, "SSID visible mais WPA3 + GCMP-256 + PMF + canal DFS + beacon rapide — sur-sécurisé"),

    (beacon(10, "",            akms=["00-0f-ac-1"], ciphers=["00-0f-ac-4"],
            mfpr="1", signal="-40"),
     True, "SSID caché + WPA2-Enterprise (serveur RADIUS) + PMF — jamais chez un civil"),
]

def run():
    print(f"\n{GRAS}{'─'*70}{RESET}")
    print(f"{GRAS}  TEST DÉTECTION PROFIL DE SÉCURITÉ — {len(SCENARIOS)} scénarios{RESET}")
    print(f"{GRAS}{'─'*70}{RESET}\n")

    ok = 0
    echecs = []

    for f, attendu, label in SCENARIOS:
        layers = f["_source"]["layers"]
        score, indices = score_securite_beacon(layers)
        resultat = est_interessant(f)
        correct = resultat == attendu

        if correct:
            ok += 1
            statut = f"{VERT}✓{RESET}"
        else:
            echecs.append((label, attendu, resultat))
            statut = f"{ROUGE}✗{RESET}"

        tag = f"{ROUGE}GARDÉ  {RESET}" if resultat else f"{JAUNE}IGNORÉ {RESET}"
        score_color = ROUGE if score >= 5 else (JAUNE if score >= 3 else VERT)
        print(f"  {statut} [{tag}] Score={score_color}{score:2d}{RESET} — {label}")

        if indices:
            for idx in indices:
                print(f"           {BLEU}→{RESET} {idx}")
        if resultat:
            desc = construire_description(f)
            print(f"         {GRAS}LLM:{RESET} {desc[:120]}...")
        print()

    print(f"{GRAS}{'─'*70}{RESET}")
    if echecs:
        print(f"  {ROUGE}{ok}/{len(SCENARIOS)} — {len(echecs)} échec(s){RESET}")
        for label, attendu, obtenu in echecs:
            print(f"  {ROUGE}✗{RESET} {label}")
            print(f"    attendu={'GARDÉ' if attendu else 'IGNORÉ'} — obtenu={'GARDÉ' if obtenu else 'IGNORÉ'}")
    else:
        print(f"  {VERT}{ok}/{len(SCENARIOS)} — tous corrects ✓{RESET}")
    print(f"{GRAS}{'─'*70}{RESET}\n")

if __name__ == "__main__":
    run()
