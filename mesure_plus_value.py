#!/usr/bin/env python3
# =============================================================================
#  mesure_plus_value.py — Quantifie l'apport réel du LLM dans la chaîne
# =============================================================================
#  Rôle       : Rejoue une suite de fenêtres de capture (pcap réels ou corpus
#               synthétique) à travers la MÊME logique que pipeline.py
#               (prefilter → aggregateur → traqueur), et mesure, sans rien
#               changer au code de production, deux choses :
#
#                 1. Le SPLIT décisionnel : quelle part des appareils est
#                    tranchée par RÈGLE déterministe (aggregateur.py) vs
#                    ESCALADÉE au LLM (cas ambigus). 100 % déterministe :
#                    ne nécessite ni tshark ni Ollama en mode démo.
#
#                 2. La PLUS-VALUE du LLM : combien de menaces tombent dans la
#                    zone ambiguë — donc INVISIBLES pour un capteur tout-script,
#                    qui n'aurait aucune règle pour les attraper. Si Ollama est
#                    joignable, on récupère le verdict réel ; sinon on rapporte
#                    la charge escaladée et on invite à relancer sur le capteur.
#
#  Usage      : python3 mesure_plus_value.py                 # corpus démo
#               python3 mesure_plus_value.py --pcaps /data/capture/done/*.pcap
#               python3 mesure_plus_value.py --no-llm        # split seul
#
#  Dépend de  : aggregateur.py, traqueur.py (toujours) ;
#               prefilter.py + tshark (mode --pcaps) ;
#               llm_analyzer.py + Ollama (verdict des cas ambigus).
# =============================================================================

import sys
import glob
import argparse

from aggregateur import agreger
from traqueur import Traqueur

# ─── Couleurs (alignées sur test_complet.py) ─────────────────────────────────
VERT, ROUGE, JAUNE, BLEU, GRIS = "\033[92m", "\033[91m", "\033[93m", "\033[94m", "\033[90m"
RESET, GRAS = "\033[0m", "\033[1m"


def titre(texte):
    print(f"\n{GRAS}{BLEU}{'═'*64}{RESET}")
    print(f"{GRAS}{BLEU}  {texte}{RESET}")
    print(f"{GRAS}{BLEU}{'═'*64}{RESET}")


# ─── Construction de trames synthétiques au format aggregateur.py ────────────
def _trame(numero, sa, subtype, ssid="", da="", signal="-65", eapol=False):
    layers = {
        "wlan.sa":               [sa],
        "wlan.fc.type_subtype":  [subtype],
        "wlan.ssid":             [ssid],
        "wlan.da":               [da],
        "radiotap.dbm_antsignal": [signal],
    }
    if eapol:
        layers["eapol.type"] = ["3"]
    return {"numero": numero, "description": "", "layers": layers}


# Vérité terrain par MAC : ce qu'un analyste humain conclurait réellement.
# Sert à juger la pertinence des décisions, pas à les produire.
VERITE = {}


def _corpus_demo():
    """
    4 fenêtres de 30 s simulant un environnement réaliste : beaucoup de civil,
    quelques attaques nettes, quelques cas authentiquement ambigus, et un
    appareil de filature qui ne se révèle que par sa PERSISTANCE inter-pcap.
    Retourne une liste de fenêtres ; chaque fenêtre est une liste de candidats.
    """
    # MACs
    M_IPHONE   = "da:a1:19:7c:00:01"   # randomisé (bit 0x02) — civil
    M_ANDROID  = "c6:2b:88:40:11:02"   # randomisé — civil
    M_PASSANT  = "fe:34:aa:90:22:03"   # randomisé — civil ponctuel
    M_DEAUTH_B = "ac:de:48:00:11:22"   # permanent — attaque deauth broadcast
    M_DEAUTH_T = "b8:27:eb:51:aa:bb"   # permanent — deauth ciblé
    M_HANDSHK  = "00:11:22:33:44:55"   # permanent — capture EAPOL
    M_RECON    = "e4:5f:01:9a:bc:de"   # permanent — scan multi-SSID
    M_COVERT   = "2c:30:33:aa:00:99"   # permanent — AP sur-sécurisé furtif
    M_CIBLE    = "44:65:0d:12:34:56"   # permanent — vise UN réseau sensible
    M_BANAL_P  = "70:4f:57:01:02:03"   # permanent — assoc banale (faux positif potentiel)
    M_FILATURE = "ee:88:c1:7f:33:44"   # randomisé MAIS persistant → filature

    VERITE.update({
        M_IPHONE: ("iPhone (vie privée)", "banal"),
        M_ANDROID: ("Android (vie privée)", "banal"),
        M_PASSANT: ("Passant randomisé", "banal"),
        M_DEAUTH_B: ("Brouillage deauth broadcast", "menace"),
        M_DEAUTH_T: ("Deauth ciblé répété", "menace"),
        M_HANDSHK: ("Capture handshake WPA", "menace"),
        M_RECON: ("Reconnaissance multi-SSID", "menace"),
        M_COVERT: ("AP sur-sécurisé furtif", "menace"),
        M_CIBLE: ("Appareil visant un réseau sensible", "menace"),
        M_BANAL_P: ("Assoc domestique permanente", "banal"),
        M_FILATURE: ("Filature randomisée persistante", "menace"),
    })

    n = [0]
    def num():
        n[0] += 1
        return n[0]

    def iphone():    return [_trame(num(), M_IPHONE, "0x0004", ssid="", signal="-58")]
    def android():   return [_trame(num(), M_ANDROID, "0x0004", ssid=s, signal="-61")
                             for s in ("Maison_5G", "Cafe_Centre")]
    def passant():   return [_trame(num(), M_PASSANT, "0x0004", ssid="", signal="-72")]
    def filature(s): return [_trame(num(), M_FILATURE, "0x0004", ssid=s, signal="-44")]

    # Fenêtre 1 — civil + une attaque nette + un cas ambigu
    f1 = []
    f1 += iphone(); f1 += android(); f1 += passant()
    f1 += [_trame(num(), M_DEAUTH_B, "0x000c", da="ff:ff:ff:ff:ff:ff", signal="-38") for _ in range(8)]
    # Cas ambigu : appareil PERMANENT qui vise un seul réseau sensible + s'authentifie, signal directionnel
    f1 += [_trame(num(), M_CIBLE, "0x0004", ssid="MINDEF_OPS_5G", signal="-29"),
           _trame(num(), M_CIBLE, "0x0004", ssid="MINDEF_OPS_5G", signal="-31"),
           _trame(num(), M_CIBLE, "0x000b", signal="-30")]
    f1 += filature("Hotel_Lobby")

    # Fenêtre 2 — civil + handshake + AP furtif (ambigu) + faux positif potentiel
    f2 = []
    f2 += iphone(); f2 += android()
    f2 += [_trame(num(), M_HANDSHK, "data", eapol=True, signal="-41") for _ in range(3)]
    # Cas ambigu : beacon SSID masqué, signal très fort (over-secured / covert)
    f2 += [_trame(num(), M_COVERT, "0x0008", ssid="", signal="-24")]
    # Cas ambigu banal : assoc domestique isolée — le LLM doit savoir l'écarter
    f2 += [_trame(num(), M_BANAL_P, "0x000b", signal="-68"),
           _trame(num(), M_BANAL_P, "0x0000", ssid="Livebox-2A30", signal="-67")]
    f2 += filature("Hotel_Lobby")

    # Fenêtre 3 — civil + deauth ciblé + reconnaissance multi-SSID
    f3 = []
    f3 += iphone(); f3 += passant()
    f3 += [_trame(num(), M_DEAUTH_T, "0x000c", da="44:65:0d:99:88:77", signal="-46") for _ in range(4)]
    f3 += [_trame(num(), M_RECON, "0x0004", ssid=s, signal="-52")
           for s in ("Box-A", "Box-B", "Box-C", "Box-D", "Box-E", "Box-F")]
    f3 += filature("Hotel_Lobby")

    # Fenêtre 4 — civil + la filature franchit le seuil de persistance (4e vue)
    f4 = []
    f4 += iphone(); f4 += android()
    f4 += filature("Hotel_Lobby")  # 4e apparition → traqueur escalade au LLM

    return [f1, f2, f3, f4]


# ─── Disponibilité d'Ollama ──────────────────────────────────────────────────
def _ollama_dispo():
    try:
        import requests
        requests.get("http://localhost:11434/api/tags", timeout=2).raise_for_status()
        return True
    except Exception:
        return False


# ─── Mesure ──────────────────────────────────────────────────────────────────
def mesurer(fenetres, avec_llm):
    traqueur = Traqueur()
    if avec_llm:
        from llm_analyzer import analyser

    # Compteurs
    c = {
        "regle_menace": 0, "regle_banal": 0,
        "llm_menace": 0, "llm_banal": 0, "llm_indispo": 0,
    }
    total = 0
    menaces_llm = []   # (mac, nom, raison) — menaces visibles UNIQUEMENT via LLM
    rate_llm_si_menace = []  # menaces réelles tombées en "banal" côté LLM

    for i, fenetre in enumerate(fenetres, 1):
        agregats = agreger(fenetre, traqueur)
        print(f"\n{GRAS}Fenêtre {i}{RESET} — {len(agregats)} appareil(s)")
        for agr in agregats:
            total += 1
            mac = agr["mac"]
            nom, verite = VERITE.get(mac, ("?", "?"))
            auto = agr["auto_class"]

            if auto is not None:
                if auto["interesting"]:
                    c["regle_menace"] += 1
                    print(f"  {VERT}⚡ RÈGLE  menace{RESET}  {GRIS}{nom:38}{RESET} {auto['category']}")
                else:
                    c["regle_banal"] += 1
                    print(f"  {GRIS}·  RÈGLE  banal   {nom:38} écarté sans LLM{RESET}")
            else:
                # Cas ambigu → un capteur TOUT-SCRIPT n'a aucune règle ici.
                if not avec_llm:
                    c["llm_indispo"] += 1
                    print(f"  {JAUNE}?  → LLM   (ambigu) {nom:36} [verdict non évalué]{RESET}")
                    continue
                analyse = analyser(agr["description"])
                if analyse.get("interesting"):
                    c["llm_menace"] += 1
                    menaces_llm.append((mac, nom, analyse.get("reason", "")))
                    print(f"  {ROUGE}✓  → LLM   MENACE {nom:38} {analyse.get('category','')}{RESET}")
                else:
                    c["llm_banal"] += 1
                    if verite == "menace":
                        rate_llm_si_menace.append((mac, nom))
                    print(f"  {GRIS}✗  → LLM   banal  {nom:38} {analyse.get('category','')}{RESET}")

    return total, c, menaces_llm, rate_llm_si_menace


def rapport(total, c, menaces_llm, rates, avec_llm, source):
    titre("BILAN — SPLIT DÉCISIONNEL (déterministe)")
    regle = c["regle_menace"] + c["regle_banal"]
    llm   = c["llm_menace"] + c["llm_banal"] + c["llm_indispo"]
    pct = lambda x: f"{100*x/total:5.1f}%" if total else "  n/a"

    print(f"\n  Décisions d'appareil analysées : {GRAS}{total}{RESET}   (source : {source})\n")
    print(f"  {GRAS}Tranché par RÈGLE  (aggregateur.py){RESET} : {GRAS}{regle:3}{RESET}  {pct(regle)}")
    print(f"       ├─ menace nette (deauth/handshake/recon) : {c['regle_menace']:3}")
    print(f"       └─ banal écarté (MAC randomisé, vie privée): {c['regle_banal']:3}")
    print(f"  {GRAS}Escaladé au LLM   (cas ambigus){RESET}     : {GRAS}{llm:3}{RESET}  {pct(llm)}")

    titre("BILAN — PLUS-VALUE DU LLM")
    print(f"\n  {GRAS}1) Économie vs capteur TOUT-LLM{RESET}")
    print(f"     Un capteur qui passerait TOUT au LLM ferait {total} inférences.")
    print(f"     Ici le LLM n'est sollicité que {llm} fois → "
          f"{GRAS}{100*(total-llm)/total:.0f}% d'inférences évitées{RESET}." if total else "")

    print(f"\n  {GRAS}2) Menaces INVISIBLES en tout-script{RESET}")
    print(f"     Ce sont les cas ambigus : aucune règle déterministe ne les")
    print(f"     attrape → un capteur sans LLM les jetterait silencieusement.")
    if not avec_llm:
        print(f"     {JAUNE}→ {c['llm_indispo']} cas escaladés, verdict non évalué "
              f"(Ollama absent).{RESET}")
        print(f"     {JAUNE}  Relance sur le capteur pour le compte réel.{RESET}")
    else:
        print(f"     {ROUGE}{GRAS}→ {len(menaces_llm)} menace(s) détectées par le seul LLM :{RESET}")
        for mac, nom, raison in menaces_llm:
            print(f"        {ROUGE}•{RESET} {nom} {GRIS}({mac}){RESET}")
            print(f"          {GRIS}{raison}{RESET}")
        if rates:
            print(f"\n     {JAUNE}Vigilance — menaces réelles classées 'banal' par le LLM : "
                  f"{len(rates)}{RESET}")
            for mac, nom in rates:
                print(f"        {JAUNE}•{RESET} {nom} {GRIS}({mac}){RESET}")

    titre("EN UNE PHRASE")
    if total:
        print(f"\n  Les RÈGLES abattent {100*regle/total:.0f}% du flux à coût nul ; "
              f"le LLM ne traite que\n  les {100*llm/total:.0f}% ambigus — et c'est "
              f"précisément là qu'il rend\n  visibles des menaces qu'aucune règle écrite "
              f"d'avance n'aurait vues.\n")


def main():
    ap = argparse.ArgumentParser(description="Mesure l'apport du LLM dans la chaîne d'analyse WiFi.")
    ap.add_argument("--pcaps", nargs="*", help="pcap réels (chaque fichier = une fenêtre). Nécessite tshark.")
    ap.add_argument("--no-llm", action="store_true", help="ne pas appeler le LLM (split déterministe seul).")
    ap.add_argument("--limit", type=int, default=0, help="ne garder que les N pcap les plus récents (0 = tous).")
    args = ap.parse_args()

    if args.pcaps:
        from prefilter import filtrer_pcap
        chemins = []
        for motif in args.pcaps:
            chemins += sorted(glob.glob(motif))
        if not chemins:
            print(f"{ROUGE}Aucun pcap trouvé.{RESET}")
            sys.exit(1)
        if args.limit > 0:
            chemins = chemins[-args.limit:]   # les N plus récents (noms horodatés triables)
        print(f"{GRIS}Lecture de {len(chemins)} pcap via tshark…{RESET}")
        fenetres = [filtrer_pcap(p) for p in chemins]
        source = f"{len(chemins)} pcap réel(s)"
    else:
        fenetres = _corpus_demo()
        source = "corpus démo (4 fenêtres)"

    avec_llm = (not args.no_llm) and _ollama_dispo()
    if not args.no_llm and not avec_llm:
        print(f"{JAUNE}⚠ Ollama injoignable sur localhost:11434 — split mesuré, "
              f"verdict LLM non évalué.{RESET}")

    titre(f"MESURE DE PLUS-VALUE — {source}")
    total, c, menaces_llm, rates = mesurer(fenetres, avec_llm)
    rapport(total, c, menaces_llm, rates, avec_llm, source)


if __name__ == "__main__":
    main()
