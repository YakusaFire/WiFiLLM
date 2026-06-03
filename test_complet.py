#!/usr/bin/env python3

import sys, os, subprocess, json, time
sys.path.insert(0, "/opt/capteur")

VERT  = "\033[92m"
ROUGE = "\033[91m"
JAUNE = "\033[93m"
BLEU  = "\033[94m"
RESET = "\033[0m"
GRAS  = "\033[1m"

resultats = []

def titre(texte):
    print(f"\n{GRAS}{BLEU}{'═'*60}{RESET}")
    print(f"{GRAS}{BLEU}  {texte}{RESET}")
    print(f"{GRAS}{BLEU}{'═'*60}{RESET}")

def test(nom, fn):
    try:
        debut = time.time()
        ok, detail = fn()
        duree = time.time() - debut
        if ok:
            print(f"  {VERT}✓{RESET} {nom} {JAUNE}({duree:.2f}s){RESET}")
            if detail:
                print(f"    {detail}")
            resultats.append((nom, True, detail))
        else:
            print(f"  {ROUGE}✗{RESET} {nom}")
            print(f"    {ROUGE}{detail}{RESET}")
            resultats.append((nom, False, detail))
    except Exception as e:
        print(f"  {ROUGE}✗{RESET} {nom}")
        print(f"    {ROUGE}EXCEPTION: {e}{RESET}")
        resultats.append((nom, False, str(e)))

# ─── 1. ENVIRONNEMENT ────────────────────────────────────────────────────────
titre("1. ENVIRONNEMENT SYSTÈME")

def test_python():
    v = sys.version_info
    return True, f"Python {v.major}.{v.minor}.{v.micro}"
test("Python version", test_python)

def test_venv():
    ok = os.path.exists("/opt/capteur/venv/bin/python")
    return ok, "/opt/capteur/venv/ présent" if ok else "venv introuvable"
test("Virtualenv Python", test_venv)

def test_requests():
    import requests
    return True, f"requests {requests.__version__}"
test("Import requests", test_requests)

def test_dirs():
    dirs = ["/opt/capteur", "/data/capture/raw", "/data/capture/interesting", "/data/capture/done"]
    manquants = [d for d in dirs if not os.path.isdir(d)]
    if manquants:
        return False, f"Manquants : {manquants}"
    return True, "Tous les dossiers présents"
test("Dossiers /data/capture/", test_dirs)

def test_scripts():
    scripts = ["prefilter.py", "llm_analyzer.py", "extractor.py", "pipeline.py", "capture.sh"]
    manquants = [s for s in scripts if not os.path.exists(f"/opt/capteur/{s}")]
    if manquants:
        return False, f"Manquants : {manquants}"
    return True, f"{len(scripts)} scripts présents"
test("Scripts déployés", test_scripts)

def test_tshark():
    r = subprocess.run(["tshark", "--version"], capture_output=True, text=True)
    line = r.stdout.split("\n")[0]
    return r.returncode == 0, line
test("tshark disponible", test_tshark)

def test_iw():
    r = subprocess.run(["/usr/sbin/iw", "--version"], capture_output=True, text=True)
    return r.returncode == 0, r.stdout.strip()
test("iw disponible", test_iw)

# ─── 2. OLLAMA & LLM ────────────────────────────────────────────────────────
titre("2. OLLAMA & QWEN")

def test_ollama_service():
    r = subprocess.run(["systemctl", "is-active", "ollama"], capture_output=True, text=True)
    ok = r.stdout.strip() == "active"
    return ok, f"Service : {r.stdout.strip()}"
test("Service Ollama actif", test_ollama_service)

def test_ollama_api():
    import requests as req
    r = req.get("http://localhost:11434/api/tags", timeout=5)
    r.raise_for_status()
    modeles = [m["name"] for m in r.json().get("models", [])]
    return len(modeles) > 0, f"Modèles : {', '.join(modeles)}"
test("API Ollama répond", test_ollama_api)

def test_qwen_charge():
    import requests as req
    r = req.get("http://localhost:11434/api/tags", timeout=5)
    modeles = [m["name"] for m in r.json().get("models", [])]
    ok = any("qwen" in m.lower() for m in modeles)
    return ok, f"qwen2.5:3b {'trouvé' if ok else 'ABSENT'}"
test("Modèle Qwen présent", test_qwen_charge)

def test_inference_rapide():
    import requests as req
    r = req.post("http://localhost:11434/api/generate", json={
        "model": "qwen2.5:3b",
        "prompt": "Réponds juste: OK",
        "stream": False,
        "options": {"num_predict": 5}
    }, timeout=30)
    r.raise_for_status()
    rep = r.json().get("response", "").strip()
    return len(rep) > 0, f"Réponse : '{rep[:40]}'"
test("Inférence LLM (ping)", test_inference_rapide)

def test_inference_json():
    import requests as req
    r = req.post("http://localhost:11434/api/generate", json={
        "model": "qwen2.5:3b",
        "system": 'Réponds uniquement en JSON : {"status": "ok"}',
        "prompt": "test",
        "stream": False,
        "format": "json",
        "options": {"num_predict": 20, "temperature": 0.1}
    }, timeout=30)
    rep = json.loads(r.json()["response"])
    return "status" in rep, f"JSON valide : {rep}"
test("Inférence LLM JSON", test_inference_json)

# ─── 3. MODULES PYTHON ──────────────────────────────────────────────────────
titre("3. MODULES DU PIPELINE")

def test_import_prefilter():
    from prefilter import est_interessant, construire_description, score_securite_beacon, filtrer_pcap
    return True, "est_interessant, construire_description, score_securite_beacon, filtrer_pcap"
test("Import prefilter.py", test_import_prefilter)

def test_import_llm():
    from llm_analyzer import analyser
    return True, "analyser()"
test("Import llm_analyzer.py", test_import_llm)

def test_import_extractor():
    from extractor import extraire
    return True, "extraire()"
test("Import extractor.py", test_import_extractor)

def test_import_pipeline():
    import importlib.util
    spec = importlib.util.spec_from_file_location("pipeline", "/opt/capteur/pipeline.py")
    return spec is not None, "pipeline.py chargeable"
test("Import pipeline.py", test_import_pipeline)

# ─── 4. LOGIQUE PRÉFILTRE ───────────────────────────────────────────────────
titre("4. LOGIQUE DU PRÉ-FILTRE")

from prefilter import est_interessant, score_securite_beacon

def frame(subtype, ssid="", signal="-65", eapol=None, akms=None, mfpr="0", mfpc="0"):
    layers = {
        "wlan.fc.type_subtype": [subtype],
        "wlan.ssid": [ssid],
        "wlan.bssid": ["AA:BB:CC:DD:EE:FF"],
        "wlan.sa": ["11:22:33:44:55:66"],
        "wlan.da": ["FF:FF:FF:FF:FF:FF"],
        "radiotap.dbm_antsignal": [signal],
        "wlan.rsn.akms": akms or [],
        "wlan.rsn.pcs": [],
        "wlan.rsn.capabilities.mfpr": [mfpr],
        "wlan.rsn.capabilities.mfpc": [mfpc],
        "wlan_mgt.ds.current_channel": ["6"],
        "wlan.beacon_interval": ["100"],
    }
    if eapol is not None:
        layers["eapol.type"] = [str(eapol)]
    return {"_source": {"layers": layers}}

cas = [
    (frame("0x0008", ssid="SFR_1234", akms=["00-0f-ac-2"]), False, "Beacon civil ignoré"),
    (frame("0x0008", ssid=""),                               True,  "Beacon SSID caché gardé"),
    (frame("0x000c"),                                        True,  "Deauth gardé"),
    (frame("0x0004", ssid="MonWifi"),                        True,  "Probe Request gardé"),
    (frame("data",   eapol=1),                               True,  "EAPOL gardé"),
    (frame("0x0008", ssid="Net", akms=["00-0f-ac-8"], mfpr="1"), True, "WPA3+PMF gardé (over-secured)"),
    (frame("0x0029"),                                        False, "ACK ignoré"),
]

ok_count = 0
for f, attendu, label in cas:
    def _test(f=f, attendu=attendu, label=label):
        res = est_interessant(f)
        if res == attendu:
            return True, label
        return False, f"{label} — attendu={'GARDÉ' if attendu else 'IGNORÉ'}, obtenu={'GARDÉ' if res else 'IGNORÉ'}"
    test(f"Filtre : {label}", _test)

# ─── 5. ANALYSE LLM SUR TRAMES RÉELLES ─────────────────────────────────────
titre("5. ANALYSE LLM — TRAMES TERRAIN")

from llm_analyzer import analyser

trames_llm = [
    ("Beacon SFR_1234 WPA2 signal -80dBm réseau domestique ordinaire",
     False, "Beacon civil → non intéressant"),
    ("Deauthentication envoyée vers tous les clients (broadcast), signal fort -38dBm",
     True, "Deauth → suspect"),
    ("Beacon réseau MASQUÉ, WPA3-SAE, PMF obligatoire, signal -18dBm antenne directionnelle. Score sur-sécurisation 10/12",
     True, "Over-secured → suspect"),
    ("Probe Request depuis 11:22:33:44:55:66 cherchant le réseau MonBureau_WiFi, signal -55dBm",
     True, "Probe → suspect"),
    ("Trame EAPOL handshake WPA2 4-way entre client et AP",
     True, "EAPOL → suspect"),
]

for desc, attendu, label in trames_llm:
    def _test_llm(desc=desc, attendu=attendu, label=label):
        res = analyser(desc)
        interesting = res.get("interesting", False)
        niveau = res.get("threat_level", "?")
        categorie = res.get("category", "?")
        detail = f"[{niveau}] {categorie}"
        if interesting == attendu:
            return True, detail
        return False, f"attendu interesting={attendu}, obtenu={interesting} — {detail}"
    test(f"LLM : {label}", _test_llm)

# ─── 6. SERVICES SYSTEMD ────────────────────────────────────────────────────
titre("6. SERVICES SYSTEMD")

def test_service(nom):
    def _t():
        r = subprocess.run(["systemctl", "is-enabled", nom], capture_output=True, text=True)
        etat = r.stdout.strip()
        ok = etat in ("enabled", "static")
        return ok, f"État : {etat}"
    return _t

test("ollama activé au boot",           test_service("ollama"))
test("capteur-pipeline activé au boot", test_service("capteur-pipeline"))

# ─── BILAN ──────────────────────────────────────────────────────────────────
titre("BILAN FINAL")

total  = len(resultats)
reussi = sum(1 for _, ok, _ in resultats if ok)
echecs = [(n, d) for n, ok, d in resultats if not ok]

print(f"\n  {GRAS}Score : {reussi}/{total}{RESET}", end="")
if not echecs:
    print(f"  {VERT}— tous les tests passent ✓{RESET}\n")
else:
    print(f"  {ROUGE}— {len(echecs)} échec(s){RESET}\n")
    print(f"  {ROUGE}Problèmes :{RESET}")
    for nom, detail in echecs:
        print(f"    {ROUGE}✗{RESET} {nom}")
        print(f"       {detail}")
    print()

print(f"  {'─'*50}")
if echecs:
    print(f"  {JAUNE}Le capteur n'est pas prêt — corriger les erreurs ci-dessus.{RESET}")
else:
    print(f"  {VERT}Le capteur est prêt — brancher la clé WiFi pour démarrer.{RESET}")
print(f"  {'─'*50}\n")
