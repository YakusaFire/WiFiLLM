#!/usr/bin/env python3
# =============================================================================
#  test_batterie.py — Batterie de tests fonctionnels + pièges
# =============================================================================
#  Rôle : Exerce TOUTES les fonctionnalités de détection (règles, traqueur,
#         LLM, résolution OUI, détection mesh) sur des scénarios
#         synthétiques à vérité-terrain connue, dont des PIÈGES délibérés.
#         Vérifie si le capteur signale bien tous les appareils hostiles
#         (rappel) et combien de faux positifs il génère.
#
#  Dépend de : aggregateur.py, traqueur.py, oui.py, llm_analyzer.py + Ollama.
#  Frames construites en mémoire (pas besoin de tshark).
# =============================================================================

import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import oui
from aggregateur import agreger
from traqueur import Traqueur
from registre_ap import RegistreAP
from llm_analyzer import analyser

V, R, J, B, GR = "\033[92m", "\033[91m", "\033[93m", "\033[94m", "\033[90m"
RST, G = "\033[0m", "\033[1m"

_n = [0]
def F(sa, subtype, ssid="", da="", signal="-60", eapol=False):
    _n[0] += 1
    L = {"wlan.sa": [sa], "wlan.fc.type_subtype": [subtype],
         "wlan.ssid": [ssid], "wlan.da": [da], "radiotap.dbm_antsignal": [signal]}
    if eapol:
        L["eapol.type"] = ["3"]
    return {"numero": _n[0], "description": "", "layers": L}

# MACs de référence
GLINET = "94:83:c4:11:22:33"   # GL Technologies (matériel maison)
SAGEM  = "80:20:da:11:22:33"   # Sagemcom (box)
ESP    = "08:3a:8d:11:22:33"   # Espressif (ESP — possible deauther)
RPI    = "b8:27:eb:11:22:33"   # Raspberry Pi (permanent générique)
PERM   = "00:11:22:33:44:55"   # permanent générique
PHONE1 = "da:a1:19:7c:00:01"   # randomisé (vie privée)
PHONE2 = "c6:2b:88:40:11:02"   # randomisé
FILAT  = "ee:88:c1:7f:33:44"   # randomisé persistant

SUB = dict(probe="0x0004", deauth="0x000c", auth="0x000b", assoc="0x0000", beacon="0x0008")

def decision(frames, mode=None, traqueur=None):
    """Évalue un lot de frames ; retourne la liste des décisions par appareil.
    (Le paramètre `mode` est conservé pour compat mais ignoré : le capteur opère
    toujours en posture terrain — les modes calibration/terrain ont été retirés.)"""
    t = traqueur if traqueur is not None else Traqueur()
    res = []
    for agr in agreger(frames, t):
        auto = agr["auto_class"]
        if auto is not None:
            res.append((agr["mac"], auto["interesting"], "règle", auto["category"], auto["reason"]))
        else:
            a = analyser(agr["description"])
            res.append((agr["mac"], a.get("interesting", False), "LLM", a.get("category", "?"), a.get("reason", "")))
    return res

# ── Scénarios : (id, description, frames, attendu_flag, hostile?, mode, piège) ──
SCEN = []
def S(sid, desc, frames, attendu, hostile, mode=None, piege=None):
    SCEN.append(dict(id=sid, desc=desc, frames=frames, attendu=attendu,
                     hostile=hostile, mode=mode, piege=piege))

# --- RÈGLES déterministes ---
S("R1", "Deauth broadcast (×8)", [F(PERM, SUB["deauth"], da="ff:ff:ff:ff:ff:ff", signal="-38") for _ in range(8)], True, True)
S("R2", "Deauth ciblé (×4)", [F(PERM, SUB["deauth"], da="aa:bb:cc:dd:ee:ff") for _ in range(4)], True, True)
S("R3", "Handshake EAPOL (×3)", [F(PERM, "data", eapol=True) for _ in range(3)], True, True)
S("R4", "Surveillance : permanent sonde 6 SSID", [F(RPI, SUB["probe"], ssid=f"Net{i}") for i in range(6)], True, True)
S("R5", "Probes wildcard depuis MAC randomisé", [F(PHONE1, SUB["probe"], ssid="") for _ in range(3)], False, False)
S("R6", "Probes ciblés depuis MAC randomisé", [F(PHONE2, SUB["probe"], ssid="Maison") for _ in range(2)], False, False)

# --- PIÈGES règles ---
S("P1", "PIÈGE : GL.iNet (ami) fait un deauth broadcast — doit QUAND MÊME être levé",
  [F(GLINET, SUB["deauth"], da="ff:ff:ff:ff:ff:ff") for _ in range(6)], True, True,
  piege="Un vendor 'ami' ne doit pas masquer une attaque dure (règle avant vendor).")
S("P2", "Permanent sonde 4 SSID → surveillance (seuil abaissé 5→4, déterministe)",
  [F(RPI, SUB["probe"], ssid=f"Z{i}") for i in range(4)], True, True,
  piege="Auparavant sous le seuil (5) → laissé au LLM (flaky) ; désormais tranché par RÈGLE.")

# --- LLM (cas ambigus) ---
S("L1", "probe_tracking : permanent vise UN SSID précis + auth, signal fort",
  [F(PERM, SUB["probe"], ssid="MINDEF_OPS_5G", signal="-29"),
   F(PERM, SUB["probe"], ssid="MINDEF_OPS_5G", signal="-30"),
   F(PERM, SUB["auth"], signal="-29")], True, True)
S("L2", "PIÈGE over-secured : beacon SSID masqué, signal très fort -24",
  [F(PERM, SUB["beacon"], ssid="", signal="-24")], True, True,
  piege="aggregateur ne transmet pas le profil de sécurité du beacon au LLM → risque de RATÉ.")
S("L3", "Assoc domestique isolée (signal faible)",
  [F(PERM, SUB["auth"], signal="-70"), F(PERM, SUB["assoc"], ssid="Livebox-2A30", signal="-69")], False, False)
S("L4", "Espressif (ESP) probes wildcard — outil d'attaque potentiel",
  [F(ESP, SUB["probe"], ssid="") for _ in range(3)], True, True,
  piege="ESP qui sonde = possible deauther bon marché ; le LLM doit le remonter.")
S("L5", "Espressif fait un deauth (×5)", [F(ESP, SUB["deauth"], da="ff:ff:ff:ff:ff:ff") for _ in range(5)], True, True)

# --- OUI (posture terrain unique — plus de mode calibration) ---
S("M1", "GL.iNet (infra domestique) sonde 6 SSID → hostile (règle surveillance)",
  [F(GLINET, SUB["probe"], ssid=f"AP{i}") for i in range(6)], True, True,
  piege="Matériel d'infra domestique en zone : toujours suspect (plus de mode calibration).")

def run():
    print(f"{G}{B}{'='*70}{RST}")
    print(f"{G}{B}  BATTERIE DE TESTS — {len(SCEN)} scénarios simples + pièges multi-fenêtres{RST}")
    print(f"{G}{B}{'='*70}{RST}")
    res_simple = []
    for s in SCEN:
        d = decision(s["frames"], s["mode"])[0]  # 1 appareil par scénario
        _, flag, chemin, cat, raison = d
        ok = (flag == s["attendu"])
        res_simple.append((s, flag, chemin, cat, raison, ok))
        tag = f"{V}OK{RST}" if ok else f"{R}KO{RST}"
        pg = f" {J}[PIÈGE]{RST}" if s["piege"] else ""
        print(f"\n[{tag}] {G}{s['id']}{RST} ({s['mode']}){pg} — {s['desc']}")
        print(f"     attendu_flag={s['attendu']}  obtenu={flag}  via {chemin}/{cat}")
        print(f"     {GR}raison: {raison[:100]}{RST}")
        if s["piege"]:
            print(f"     {J}piège: {s['piege']}{RST}")

    # --- Pièges multi-fenêtres ---
    print(f"\n{G}{B}{'─'*70}{RST}\n{G}  PIÈGES MULTI-FENÊTRES (traqueur){RST}\n{G}{B}{'─'*70}{RST}")

    # TR1 : téléphone randomisé persistant sur 4 fenêtres → escalade au LLM
    t = Traqueur()
    tr1_flag = None
    for w in range(1, 5):
        d = decision([F(FILAT, SUB["probe"], ssid="Hotel_Lobby", signal="-44")], traqueur=t)[0]
        tr1_flag = d[1]; tr1_chemin = d[2]; tr1_cat = d[3]; tr1_raison = d[4]
    tr1_ok = (tr1_flag == False)
    tag = f"{V}OK{RST}" if tr1_ok else f"{R}KO{RST}"
    print(f"\n[{tag}] {G}TR1{RST} {J}[PIÈGE]{RST} — Téléphone randomisé PERSISTANT (4 fenêtres) → escaladé, doit rester BÉNIN")
    print(f"     attendu_flag=False  obtenu={tr1_flag}  via {tr1_chemin}/{tr1_cat}")
    print(f"     {GR}raison: {tr1_raison[:100]}{RST}")
    print(f"     {J}piège: le v1 le classait menace (faux positif) ; le correctif v2 doit l'écarter.{RST}")

    # E1 : evil twin — ROGUE (nouveau BSSID, signal fort) usurpe un SSID établi.
    # Le registre détecte le conflit et ESCALADE au LLM avec la comparaison ;
    # le verdict evil_twin final (qui dépend d'Ollama) est validé sur le UP².
    # NB : ROGUE a un vendor DIFFÉRENT de LEGIT → ce n'est pas un mesh (même vendor).
    LEGIT = "80:20:da:aa:aa:aa"; ROGUE = "00:de:ad:be:ef:00"
    reg = RegistreAP(chemin=os.path.join(tempfile.mkdtemp(), "reg.json"))
    for _ in range(4):                      # LEGIT établi sur 4 fenêtres (antériorité)
        reg.nouvelle_fenetre()
        agreger([F(LEGIT, SUB["beacon"], ssid="Wifi_Cafe", signal="-68")], Traqueur(), reg)
    reg.nouvelle_fenetre()                  # fenêtre où le pirate apparaît
    agr_e1 = agreger([F(LEGIT, SUB["beacon"], ssid="Wifi_Cafe", signal="-68"),
                      F(ROGUE, SUB["beacon"], ssid="Wifi_Cafe", signal="-30")], Traqueur(), reg)
    rogue_agr = next((a for a in agr_e1 if a["mac"] == ROGUE), None)
    legit_agr = next((a for a in agr_e1 if a["mac"] == LEGIT), None)
    e1_escalade    = rogue_agr is not None and rogue_agr["auto_class"] is None
    e1_comparaison = rogue_agr is not None and "COMPARAISON evil-twin" in rogue_agr["description"]
    e1_legit_benin = (legit_agr is not None and legit_agr["auto_class"] is not None
                      and not legit_agr["auto_class"]["interesting"])
    e1_ok = e1_escalade and e1_comparaison and e1_legit_benin
    tag = f"{V}OK{RST}" if e1_ok else f"{R}KO{RST}"
    print(f"\n[{tag}] {G}E1{RST} {J}[evil twin]{RST} — ROGUE usurpe 'Wifi_Cafe' (signal -30 vs réf -68)")
    print(f"     ROGUE escaladé au LLM (auto=None) : {e1_escalade} | comparaison injectée : {e1_comparaison}")
    print(f"     Référence LEGIT laissée bénigne   : {e1_legit_benin}")
    if rogue_agr is not None and rogue_agr["auto_class"] is None:
        print(f"     {GR}…{rogue_agr['description'][-200:]}{RST}")

    # E2 : MESH — 2 AP même SSID et MÊME fabricant (kit mesh / multi-AP). En
    # posture terrain, une infra multi-AP est inhabituelle → SUSPECT, verdict
    # DÉTERMINISTE (catégorie 'mesh', sans LLM). Nécessite l'OUI résolu (manuf) :
    # validé sur le UP². En régime établi, les DEUX AP doivent être levés.
    reg2 = RegistreAP(chemin=os.path.join(tempfile.mkdtemp(), "reg.json"))
    AP_A, AP_B = "80:20:da:aa:aa:aa", "80:20:da:bb:bb:bb"
    for _ in range(2):
        reg2.nouvelle_fenetre()
        agreger([F(AP_A, SUB["beacon"], ssid="Entreprise", signal="-55"),
                 F(AP_B, SUB["beacon"], ssid="Entreprise", signal="-58")], Traqueur(), reg2)
    reg2.nouvelle_fenetre()
    agr_e2 = agreger([F(AP_A, SUB["beacon"], ssid="Entreprise", signal="-55"),
                      F(AP_B, SUB["beacon"], ssid="Entreprise", signal="-58")], Traqueur(), reg2)
    e2_ok = all(a["auto_class"] is not None and a["auto_class"]["interesting"]
                and a["auto_class"]["category"] == "mesh" for a in agr_e2)
    tag = f"{V}OK{RST}" if e2_ok else f"{R}KO{RST}"
    print(f"\n[{tag}] {G}E2{RST} {J}[mesh]{RST} — 2 AP même SSID MÊME fabricant → SUSPECT (catégorie mesh)")
    print(f"     Les deux AP levés en mesh (régime établi) : {e2_ok}")
    if not e2_ok:
        for a in agr_e2:
            ac = a["auto_class"]
            print(f"     {GR}{a['mac']} → {ac and (ac['category'], ac['interesting'])}{RST}")

    # ── BILAN ──
    print(f"\n{G}{B}{'='*70}{RST}\n{G}{B}  BILAN — DÉTECTION DES APPAREILS HOSTILES{RST}\n{G}{B}{'='*70}{RST}")
    hostiles = [(s, flag) for (s, flag, *_ ) in res_simple if s["hostile"]]
    benins   = [(s, flag) for (s, flag, *_ ) in res_simple if not s["hostile"]]
    fn = [s["id"] for (s, flag) in hostiles if not flag]   # hostiles ratés (CRITIQUE)
    fp = [s["id"] for (s, flag) in benins if flag]          # fausses alertes
    tp = sum(1 for (s, flag) in hostiles if flag)
    tn = sum(1 for (s, flag) in benins if not flag)
    if not tr1_ok:
        fp.append("TR1")
    print(f"\n  Hostiles correctement signalés (rappel) : {tp}/{len(hostiles)}")
    print(f"  Bénins correctement ignorés             : {tn}/{len(benins)} (+TR1)")
    print(f"  {R}Hostiles RATÉS (faux négatifs)          : {fn or 'aucun'}{RST}")
    print(f"  {J}Fausses alertes (faux positifs)         : {fp or 'aucune'}{RST}")
    print(f"\n  {GR}Note : E1/E2 (evil twin) — détection via registre persistant SSID→BSSID ;{RST}")
    print(f"  {GR}       le verdict evil_twin final (Ollama) se valide sur le UP².{RST}")

if __name__ == "__main__":
    run()
