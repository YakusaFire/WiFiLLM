#!/usr/bin/env python3
# =============================================================================
#  test_batterie.py — Batterie de tests fonctionnels + pièges
# =============================================================================
#  Rôle : Exerce TOUTES les fonctionnalités de détection (règles, traqueur,
#         LLM, résolution OUI, modes calibration/terrain) sur des scénarios
#         synthétiques à vérité-terrain connue, dont des PIÈGES délibérés.
#         Vérifie si le capteur signale bien tous les appareils hostiles
#         (rappel) et combien de faux positifs il génère.
#
#  Dépend de : aggregateur.py, traqueur.py, oui.py, llm_analyzer.py + Ollama.
#  Frames construites en mémoire (pas besoin de tshark).
# =============================================================================

import oui
from aggregateur import agreger
from traqueur import Traqueur
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

def decision(frames, mode="calibration", traqueur=None):
    """Évalue un lot de frames ; retourne la liste des décisions par appareil."""
    oui.MODE = mode
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
def S(sid, desc, frames, attendu, hostile, mode="calibration", piege=None):
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
S("P2", "PIÈGE évasion de seuil : permanent sonde 4 SSID (< seuil 5)",
  [F(RPI, SUB["probe"], ssid=f"Z{i}") for i in range(4)], True, True,
  piege="Juste sous le seuil surveillance — la règle ne tire pas, le LLM doit rattraper.")

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

# --- OUI + MODES ---
S("M1", "PIÈGE FP : GL.iNet (ami) sonde 6 SSID en CALIBRATION",
  [F(GLINET, SUB["probe"], ssid=f"AP{i}") for i in range(6)], False, False, mode="calibration",
  piege="Matériel maison, mais la règle surveillance (≥5 SSID) ignore le mode → FP probable.")
S("M2", "GL.iNet sonde 6 SSID en TERRAIN (hostile attendu)",
  [F(GLINET, SUB["probe"], ssid=f"AP{i}") for i in range(6)], True, True, mode="terrain")
S("M3", "GL.iNet probe bénin (1 SSID) en CALIBRATION → bénin",
  [F(GLINET, SUB["probe"], ssid="Bureau") for _ in range(2)], False, False, mode="calibration")
S("M4", "GL.iNet probe (1 SSID) en TERRAIN → suspect",
  [F(GLINET, SUB["probe"], ssid="Bureau") for _ in range(2)], True, True, mode="terrain")

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
    oui.MODE = "calibration"
    t = Traqueur()
    tr1_flag = None
    for w in range(1, 5):
        d = decision([F(FILAT, SUB["probe"], ssid="Hotel_Lobby", signal="-44")], "calibration", traqueur=t)[0]
        tr1_flag = d[1]; tr1_chemin = d[2]; tr1_cat = d[3]; tr1_raison = d[4]
    tr1_ok = (tr1_flag == False)
    tag = f"{V}OK{RST}" if tr1_ok else f"{R}KO{RST}"
    print(f"\n[{tag}] {G}TR1{RST} {J}[PIÈGE]{RST} — Téléphone randomisé PERSISTANT (4 fenêtres) → escaladé, doit rester BÉNIN")
    print(f"     attendu_flag=False  obtenu={tr1_flag}  via {tr1_chemin}/{tr1_cat}")
    print(f"     {GR}raison: {tr1_raison[:100]}{RST}")
    print(f"     {J}piège: le v1 le classait menace (faux positif) ; le correctif v2 doit l'écarter.{RST}")

    # E1 : evil twin — 2 beacons même SSID, BSSID différents
    oui.MODE = "calibration"
    LEGIT = "80:20:da:aa:aa:aa"; ROGUE = "00:de:ad:be:ef:00"
    d_e1 = decision([F(LEGIT, SUB["beacon"], ssid="Wifi_Cafe", signal="-68"),
                     F(ROGUE, SUB["beacon"], ssid="Wifi_Cafe", signal="-30")], "calibration")
    rogue_flag = next((x[1] for x in d_e1 if x[0] == ROGUE), False)
    print(f"\n[{J}GAP{RST}] {G}E1{RST} {J}[PIÈGE]{RST} — Evil twin : 2 AP même SSID 'Wifi_Cafe', BSSID différents")
    print(f"     AP pirate (ROGUE {ROGUE}) signalé ? {rogue_flag}  (attendu : RATÉ, gap documenté)")
    for mac, flag, chemin, cat, raison in d_e1:
        print(f"     {GR}{mac} → flag={flag} {chemin}/{cat} : {raison[:70]}{RST}")

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
    print(f"\n  {GR}Note : E1 (evil twin) hors comptage — gap connu et documenté.{RST}")

if __name__ == "__main__":
    run()
