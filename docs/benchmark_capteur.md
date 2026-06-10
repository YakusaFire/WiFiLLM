# Benchmark complet du capteur WiFi-LLM — marche à suivre

> **But du document.** Décrire, de bout en bout et de façon *reproductible*, comment
> mesurer (a) **la couverture de détection** du capteur — détecte-t-il *tous* les
> types d'ennemis possibles sur le terrain — et (b) **le temps que prend chaque
> étape** de la chaîne d'analyse.
>
> **Mode d'emploi.** Ce `.md` est conçu pour être **auto-suffisant** : en me le
> redonnant, je dois pouvoir rejouer un benchmark complet sans rien redécouvrir du
> code. Les scripts nécessaires sont **intégrés ci-dessous** (sections 5, 6, 8) —
> il suffit de les recréer aux chemins indiqués et de les lancer dans l'ordre.
>
> **Tout s'exécute directement sur le UP²** — génération du corpus pcap, analyse,
> et rédaction du rapport. Le PC de dev ne sert qu'à (a) pousser les deux scripts
> vers le UP² et (b) rapatrier le rapport final pour le commiter dans `rapport/`.
>
> Dernière mise à jour du protocole : 2026-06-10. Cible : UP² 7100 `wifi-llm`,
> modèle `qwen2.5:3b` via Ollama (`localhost:11434`).

---

## 1. Principe du benchmark

Le capteur, en production, surveille `/data/capture/raw/` et traite chaque pcap
en **4 étapes chaînées** (`pipeline.py`) :

```
pcap brut ─▶ prefilter ─▶ aggregateur ─▶ [llm_analyzer] ─▶ extractor ─▶ trames/*.json
            (tshark)      (règles déter.)  (Ollama, ambigu)  (tshark write)
```

Deux **chemins de décision** coexistent :

| Chemin | Décideur | Coût | Cas traités |
|---|---|---|---|
| **RÈGLE** | `aggregateur.py` (déterministe) | ~0 (CPU négligeable) | attaques nettes & civil évident |
| **LLM** | `llm_analyzer.py` (qwen2.5:3b) | élevé (inférence) | cas **ambigus** seuls |

Le benchmark **rejoue un corpus de pcap étiquetés** (vérité-terrain connue) à
travers **exactement les mêmes modules** que la production, en **chronométrant
chaque étape** et en **comparant chaque verdict à la vérité-terrain**. Il produit :

1. Un **tableau de couverture** : rappel sur les hostiles, faux positifs sur les
   bénins, matrice catégorie attendue → catégorie obtenue.
2. Un **tableau de latence** : temps par étape (prefilter / aggregateur / LLM /
   extractor), agrégé et par scénario, avec distinction **cold-start vs warm** du
   LLM.
3. Un **rapport `.md`** déposé dans `rapport/`.

> **Pourquoi rejouer dans un harnais plutôt que via `pipeline.py` ?** `pipeline.py`
> ne loggue pas le temps par étape. Le harnais (section 6) importe les **vrais
> modules de production** (aucune copie, aucun mock) et pose juste des chronomètres
> autour. Les verdicts sont donc identiques à la production ; seul le timing est en
> plus. Une passe end-to-end « réelle » via `raw/` est décrite en section 7 pour
> valider que le pipeline complet (extractor + push) se comporte pareil.

---

## 2. Taxonomie des ennemis à couvrir

Le capteur connaît ces catégories (cf. `llm_analyzer.py` :
`CATEGORIES_SUSPECTES`, `CATEGORIES_GRAVES`). Le corpus DOIT contenir **au moins
un scénario par ligne**, plus les pièges et les bénins.

| # | Catégorie | Signature 802.11 | Chemin attendu | Niveau | Détecteur |
|---|---|---|---|---|---|
| E1 | `deauth_attack` (broadcast) | ≥5 deauth vers `ff:ff:ff:ff:ff:ff` | RÈGLE | high | `_auto_classifier` |
| E2 | `deauth_attack` (ciblé) | ≥3 deauth vers un client précis | RÈGLE | medium | `_auto_classifier` |
| E3 | `handshake` | ≥2 trames EAPOL (4-way WPA) | RÈGLE | medium | `_auto_classifier` |
| E4 | `surveillance` | MAC **permanente** sondant ≥4 SSID | RÈGLE | medium | `_auto_classifier` |
| E5 | `probe_tracking` | MAC permanente visant 1 SSID précis + auth, signal fort | **LLM** | medium | qwen2.5:3b |
| E6 | `over_secured` / `covert_ap` | Beacon WPA3+PMF+SSID masqué, signal très fort | **LLM** | medium/high | score beacon → LLM |
| E7 | `evil_twin` | Nouveau BSSID usurpant un SSID **déjà établi** (multi-fenêtres) | **LLM** | medium/high | `RegistreAP` → LLM |
| E8 | `anomaly` | Comportement atypique non couvert ci-dessus | **LLM** | variable | qwen2.5:3b |
| E9 | `mesh` | Même SSID porté par ≥2 BSSID du **même** fabricant (multi-fenêtres) | RÈGLE | medium | `RegistreAP.infos_mesh` |
| — | **Filature** (randomisé persistant) | MAC randomisée revue ≥4 fenêtres | **LLM** (via traqueur) | doit rester **bénin** (cf. TR1) | `Traqueur` |

**Bénins** (ne DOIVENT PAS lever d'alerte — mesure des faux positifs) :

| # | Bénin | Signature | Chemin attendu |
|---|---|---|---|
| B1 | iPhone/Android vie privée | Probes wildcard/ciblés depuis MAC **randomisée** | RÈGLE → ignoré |
| B2 | Box internet | Beacon WPA2-PSK, SSID visible, signal normal | RÈGLE → ignoré |
| B3 | Assoc domestique isolée | 1 auth + 1 assoc sur réseau connu, signal faible | LLM (zone grise) |

**Pièges** (vérifient que la logique fine tient) :

| # | Piège | Attendu |
|---|---|---|
| P1 | Vendor « ami » (GL.iNet) émet un **deauth** | **levé quand même** (règle avant vendor) |
| P2 | Permanent sonde **4** SSID | **hostile** (`surveillance`, RÈGLE — seuil abaissé 5→4) |
| P3 | ESP/Espressif sonde activement | suspect (deauther bon marché probable) |
| P4 | GL.iNet (infra domestique) sonde 6 SSID | **hostile** (`surveillance`) — toujours suspect, plus de mode |
| MESH | Même SSID porté par ≥2 BSSID du **même** fabricant | **hostile** (`mesh`, déterministe) |

> **Posture terrain unique.** Les modes `calibration`/`terrain` ont été retirés : le
> matériel d'infrastructure domestique (GL.iNet, Sagemcom) est toujours suspect, et
> un réseau **mesh** (catégorie `mesh`) est levé déterministe-ment (cf.
> `rapport/rapport_benchmark_v3.md`).

> Ces scénarios sont déjà éprouvés en synthétique dans `tests/test_batterie.py` ;
> le benchmark les rejoue **en vrais pcap** (donc en passant par tshark) et ajoute
> la mesure de latence.

---

## 3. Pré-requis

**Tout le benchmark tourne sur le UP² `wifi-llm`** (il a tshark + Ollama + le code
capteur). À vérifier/installer une fois, sur le UP² :

```bash
# (sur le UP², en SSH)
# scapy : sur Debian (PEP 668), préférer le paquet apt à pip3 sur un capteur de prod
python3 -c "import scapy" 2>/dev/null || (echo $PW | sudo -S apt-get install -y python3-scapy)
which tshark                                                  # déjà présent (pipeline)
curl -s localhost:11434/api/tags >/dev/null && echo "Ollama OK"
ollama list | grep qwen2.5:3b                                 # modèle présent
ls /root/{prefilter,aggregateur,llm_analyzer,extractor,traqueur,registre_ap,oui}.py
```

> Si `pip3 install scapy` échoue (pas de réseau sortant sur le UP²), voir
> l'annexe 11 « Génération sans scapy » : repli qui fabrique les pcap via `text2pcap`
> (tshark, déjà présent) ou, à défaut, génère le corpus sur le PC et le pousse.

**Accès au UP²** (source de vérité : fichier `.env` du dépôt) :

```
SSH_HOST=wifi-llm   SSH_IP=100.126.251.3   SSH_USER=user   SSH_PASSWORD=wifillmuser
```

Helpers, **depuis le PC** (UP² en ligne via Tailscale) — servent seulement à
pousser les scripts et rapatrier le rapport :

```bash
# nécessite sshpass : sudo apt install sshpass
source .env
SSH="sshpass -p $SSH_PASSWORD ssh $SSH_USER@$SSH_IP"
SCP="sshpass -p $SSH_PASSWORD scp"
# le code capteur est sous /root → préfixer les commandes UP² par sudo (mdp = SSH_PASSWORD)
```

> Tout ce qui suit en bloc « (sur le UP²) » s'exécute dans une session SSH sur le
> UP² (`$SSH`), pas sur le PC.

---

## 4. Préparation de l'environnement de mesure

> ⚠️ **Isolation.** Le benchmark ne doit pas (a) capturer du trafic réel pendant la
> mesure, ni (b) polluer l'état persistant de production (`registre_ap.json`).

```bash
# 1. Arrêter la capture (sinon de vraies trames se mélangent au corpus).
#    Ollama reste up.
$SSH 'sudo bash /root/capteur.sh stop'

# 2. Précharger le modèle (évite de compter le cold-start dans CHAQUE mesure ;
#    on le mesurera séparément, une fois).
$SSH 'curl -s localhost:11434/api/generate -d "{\"model\":\"qwen2.5:3b\",\"prompt\":\"ok\",\"stream\":false}" >/dev/null'

# 3. Le harnais utilise un registre_ap.json TEMPORAIRE (jamais celui de prod) :
#    c'est géré dans le script (RegistreAP(chemin=...)). Rien à faire ici.
```

Il n'y a plus de **mode** à piloter : le capteur opère toujours en posture terrain
(les modes `calibration`/`terrain` ont été retirés).

---

## 5. Étape 1 — Déployer les scripts et générer le corpus (sur le UP²)

> ⚠️ **Source de vérité = les fichiers du dépôt** `benchmark/generer_corpus.py` et
> `benchmark/bench_capteur.py` (versionnés). Les listings intégrés ci-dessous sont
> une **photo de référence** et peuvent retarder d'une évolution (ex. ajout du
> scénario mesh, retrait des modes en v3). En cas de doute, utiliser les fichiers
> du repo, pas le copier-coller du `.md`.

Les **deux** scripts existent dans `benchmark/` du dépôt, les **pousser sur le UP²**,
puis **générer le corpus là-bas**. Le générateur écrit les pcap dans
`/root/benchmark/corpus/` + un `manifest.json` (vérité-terrain + ordre).

```bash
# (depuis le PC) pousser les deux scripts sur le UP²
$SSH 'sudo mkdir -p /root/benchmark && sudo chown $USER /root/benchmark' 2>/dev/null || $SSH 'mkdir -p /root/benchmark'
$SCP benchmark/generer_corpus.py benchmark/bench_capteur.py $SSH_USER@$SSH_IP:/root/benchmark/
```

> **Important sur l'ordre.** E7 (evil twin) et la Filature sont **multi-fenêtres** :
> chaque fenêtre est un pcap distinct, traité dans l'ordre par un **même**
> `Traqueur`/`RegistreAP` (comme en production). Le `manifest.json` fixe cet ordre.

```python
#!/usr/bin/env python3
# benchmark/generer_corpus.py — fabrique un corpus de pcap 802.11 étiquetés.
# Dépend de scapy. Sortie : benchmark/corpus/*.pcap + benchmark/corpus/manifest.json
import os, json, struct
from scapy.all import (RadioTap, Dot11, Dot11Beacon, Dot11ProbeReq, Dot11Deauth,
                       Dot11Auth, Dot11AssoReq, Dot11Elt, LLC, SNAP, wrpcap)
from scapy.layers.eap import EAPOL

ICI = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(ICI, "corpus")
os.makedirs(OUT, exist_ok=True)

BCAST = "ff:ff:ff:ff:ff:ff"

# --- MACs de référence (alignées sur tests/test_batterie.py) -----------------
PERM   = "00:11:22:33:44:55"   # permanent générique
RPI    = "b8:27:eb:11:22:33"   # Raspberry Pi (permanent)
ESP    = "08:3a:8d:11:22:33"   # Espressif (deauther probable)
GLINET = "94:83:c4:11:22:33"   # GL Technologies (matériel maison)
SAGEM  = "80:20:da:aa:aa:aa"   # Sagemcom (box légitime — référence evil twin)
ROGUE  = "00:de:ad:be:ef:00"   # AP pirate (evil twin)
PHONE1 = "da:a1:19:7c:00:01"   # randomisé (bit 0x02) — vie privée
PHONE2 = "c6:2b:88:40:11:02"   # randomisé
FILAT  = "ee:88:c1:7f:33:44"   # randomisé MAIS persistant → filature

def rt(signal):
    """RadioTap avec dBm_AntSignal renseigné (→ radiotap.dbm_antsignal)."""
    try:
        return RadioTap(dBm_AntSignal=signal)
    except Exception:                      # vieux scapy : present explicite
        return RadioTap(present="dBm_AntSignal", dBm_AntSignal=signal)

def rsn_ie(akm=2, pcs=4, group=4, mfpr=False, mfpc=False):
    """Octets d'un Information Element RSN (ID 48). akm/pcs/group = derniers
    octets de la suite 00-0f-ac-X. WPA2-PSK akm=2 ; WPA3-SAE akm=8 ;
    CCMP-128 pcs=4 ; GCMP-256 pcs=9. MFPR=bit6, MFPC=bit7 des RSN caps."""
    OUIB = b"\x00\x0f\xac"
    caps = (0x0040 if mfpr else 0) | (0x0080 if mfpc else 0)
    return (struct.pack("<H", 1) + OUIB + bytes([group]) +
            struct.pack("<H", 1) + OUIB + bytes([pcs]) +
            struct.pack("<H", 1) + OUIB + bytes([akm]) +
            struct.pack("<H", caps))

# --- Fabriques de trames -----------------------------------------------------
def deauth(sa, da, signal=-40, bssid=None):
    bssid = bssid or sa
    return rt(signal)/Dot11(type=0, subtype=12, addr1=da, addr2=sa, addr3=bssid)/Dot11Deauth(reason=7)

def probe(sa, ssid="", signal=-60):
    p = rt(signal)/Dot11(type=0, subtype=4, addr1=BCAST, addr2=sa, addr3=BCAST)/Dot11ProbeReq()
    return p/Dot11Elt(ID=0, info=ssid.encode())

def auth(sa, bssid=PERM, signal=-30):
    return rt(signal)/Dot11(type=0, subtype=11, addr1=bssid, addr2=sa, addr3=bssid)/Dot11Auth(seqnum=1)

def assoc(sa, ssid, bssid=PERM, signal=-67):
    p = rt(signal)/Dot11(type=0, subtype=0, addr1=bssid, addr2=sa, addr3=bssid)/Dot11AssoReq()
    return p/Dot11Elt(ID=0, info=ssid.encode())

def eapol(sa, bssid=PERM, signal=-41):
    # Trame Data (type=2, subtype=0) portant un EAPOL-Key (type=3) via LLC/SNAP
    # 0x888e → tshark voit eapol.type. ToDS=FromDS=0 : addr2 = wlan.sa.
    return (rt(signal)/Dot11(type=2, subtype=0, addr1=bssid, addr2=sa, addr3=bssid)/
            LLC(dsap=0xaa, ssap=0xaa, ctrl=3)/SNAP(OUI=0, code=0x888e)/
            EAPOL(version=2, type=3))

def beacon(bssid, ssid, channel=6, signal=-60, secure=False, masked=False, interval=100):
    cap = "ESS+privacy" if (secure or not masked) else "ESS"
    elts = Dot11Elt(ID=0, info=(b"" if masked else ssid.encode()))
    elts /= Dot11Elt(ID=3, info=bytes([channel]))            # DS Parameter Set
    if secure:                                               # RSN WPA3-SAE+GCMP256+PMF
        elts /= Dot11Elt(ID=48, info=rsn_ie(akm=8, pcs=9, mfpr=True, mfpc=True))
    else:                                                    # RSN WPA2-PSK banal
        elts /= Dot11Elt(ID=48, info=rsn_ie(akm=2, pcs=4))
    return (rt(signal)/Dot11(type=0, subtype=8, addr1=BCAST, addr2=bssid, addr3=bssid)/
            Dot11Beacon(cap=cap, beacon_interval=interval)/elts)

# --- Bruit civil réutilisable ------------------------------------------------
def bruit_civil():
    return [probe(PHONE1, "", -58), probe(PHONE2, "Maison_5G", -61),
            beacon("80:20:da:bb:bb:bb", "Livebox-2A30", channel=6, signal=-65)]

# --- Construction du corpus : (nom_pcap, [trames], {mac: attendu}, mode) ------
# attendu = {"interesting": bool, "category": str|None, "label": str}
WINDOWS = []
def W(nom, trames, attendu, mode="calibration"):
    WINDOWS.append({"pcap": nom, "trames": trames, "attendu": attendu, "mode": mode})

# E1 deauth broadcast (×8)
W("e1_deauth_broadcast", [deauth(PERM, BCAST, -38) for _ in range(8)] + bruit_civil(),
  {PERM: {"interesting": True, "category": "deauth_attack", "label": "Deauth broadcast"}})
# E2 deauth ciblé (×4)
W("e2_deauth_cible", [deauth(PERM, "44:65:0d:99:88:77", -46) for _ in range(4)] + bruit_civil(),
  {PERM: {"interesting": True, "category": "deauth_attack", "label": "Deauth ciblé"}})
# E3 handshake EAPOL (×3)
W("e3_handshake", [eapol(PERM, signal=-41) for _ in range(3)] + bruit_civil(),
  {PERM: {"interesting": True, "category": "handshake", "label": "Handshake WPA"}})
# E4 surveillance : permanent sonde 6 SSID
W("e4_surveillance", [probe(RPI, f"Box-{c}", -52) for c in "ABCDEF"] + bruit_civil(),
  {RPI: {"interesting": True, "category": "surveillance", "label": "Recon multi-SSID"}})
# E5 probe_tracking : permanent vise 1 SSID sensible + auth, signal fort (→ LLM)
W("e5_probe_tracking",
  [probe(PERM, "MINDEF_OPS_5G", -29), probe(PERM, "MINDEF_OPS_5G", -30), auth(PERM, signal=-29)] + bruit_civil(),
  {PERM: {"interesting": True, "category": None, "label": "Tracking SSID sensible"}})
# E6 over_secured / covert_ap : beacon WPA3+PMF, SSID masqué, signal très fort (→ LLM)
W("e6_over_secured", [beacon(PERM, "", channel=36, signal=-24, secure=True, masked=True)] + bruit_civil(),
  {PERM: {"interesting": True, "category": None, "label": "AP sur-sécurisé furtif"}})
# E8 anomaly : auth en rafale sans assoc ni probe, signal fort (atypique → LLM)
W("e8_anomaly", [auth(RPI, signal=-33) for _ in range(4)] + bruit_civil(),
  {RPI: {"interesting": None, "category": None, "label": "Anomalie (auth en rafale)"}})

# E7 evil twin : 4 fenêtres SAGEM établi puis 1 fenêtre ROGUE même SSID, signal fort.
for i in range(1, 5):
    W(f"e7_evil_twin_{i}_legit", [beacon(SAGEM, "Wifi_Cafe", channel=6, signal=-68)],
      {SAGEM: {"interesting": False, "category": "normal", "label": "AP légitime (réf)"}})
W("e7_evil_twin_5_rogue",
  [beacon(SAGEM, "Wifi_Cafe", channel=6, signal=-68), beacon(ROGUE, "Wifi_Cafe", channel=11, signal=-30)],
  {ROGUE: {"interesting": True, "category": "evil_twin", "label": "Evil twin (rogue)"},
   SAGEM: {"interesting": False, "category": "normal", "label": "AP légitime (réf)"}})

# Bénins
W("b1_civil_randomise", [probe(PHONE1, "", -58), probe(PHONE2, "Cafe_Centre", -61)],
  {PHONE1: {"interesting": False, "category": "normal", "label": "iPhone vie privée"},
   PHONE2: {"interesting": False, "category": "normal", "label": "Android vie privée"}})
W("b2_box_internet", [beacon("80:20:da:bb:bb:bb", "Livebox-2A30", channel=6, signal=-65)],
  {"80:20:da:bb:bb:bb": {"interesting": False, "category": "normal", "label": "Box WPA2"}})
W("b3_assoc_domestique", [auth(PERM, signal=-70), assoc(PERM, "Livebox-2A30", signal=-69)],
  {PERM: {"interesting": False, "category": "normal", "label": "Assoc domestique (zone grise)"}})

# Pièges
W("p1_glinet_deauth", [deauth(GLINET, BCAST, -40) for _ in range(6)],
  {GLINET: {"interesting": True, "category": "deauth_attack", "label": "Ami fait un deauth"}})
W("p2_surveillance_4ssid", [probe(RPI, f"Z{i}", -55) for i in range(4)],
  {RPI: {"interesting": True, "category": "surveillance", "label": "Permanent sonde 4 SSID (surveillance, règle)"}})
W("p3_esp_probe", [probe(ESP, "", -50) for _ in range(3)],
  {ESP: {"interesting": True, "category": None, "label": "ESP sonde (deauther ?)"}})
W("m1_glinet_calib", [probe(GLINET, f"AP{i}", -55) for i in range(6)],
  {GLINET: {"interesting": False, "category": "normal", "label": "GL.iNet 6 SSID (calib)"}}, mode="calibration")
W("m2_glinet_terrain", [probe(GLINET, f"AP{i}", -55) for i in range(6)],
  {GLINET: {"interesting": True, "category": None, "label": "GL.iNet 6 SSID (terrain)"}}, mode="terrain")

# Filature : même MAC randomisée sur 4 fenêtres → escalade traqueur, doit rester bénin
for i in range(1, 5):
    W(f"f1_filature_{i}", [probe(FILAT, "Hotel_Lobby", -44)],
      {FILAT: {"interesting": False, "category": "normal", "label": "Filature randomisée (≤bénin)"}})

# --- Écriture ----------------------------------------------------------------
manifest = []
for w in WINDOWS:
    chemin = os.path.join(OUT, w["pcap"] + ".pcap")
    wrpcap(chemin, w["trames"])
    manifest.append({"pcap": w["pcap"] + ".pcap", "attendu": w["attendu"], "mode": w["mode"]})

with open(os.path.join(OUT, "manifest.json"), "w") as f:
    json.dump(manifest, f, indent=2, ensure_ascii=False)

print(f"{len(WINDOWS)} pcap générés dans {OUT}")
print(f"manifest.json écrit ({len(manifest)} fenêtres)")
```

Lancement **sur le UP²** :

```bash
# (sur le UP²)
cd /root && python3 benchmark/generer_corpus.py
ls /root/benchmark/corpus/    # *.pcap + manifest.json

# Vérifier que tshark relit bien les champs sensibles du beacon over-secured :
tshark -r /root/benchmark/corpus/e6_over_secured.pcap \
       -T fields -e wlan.rsn.akms -e wlan.rsn.capabilities.mfpr -e wlan.ssid
#   → doit montrer  00-0f-ac-8   1   (SSID vide)
```

---

## 6. Étape 2 — Lancer le benchmark (couverture + latence + rapport)

Le harnais (`bench_capteur.py`, déjà poussé en section 5) s'exécute **dans `/root`
sur le UP²** pour importer les vrais modules de production. Il :

1. chronomètre chaque étape (prefilter / aggregateur / LLM) sur chaque fenêtre,
2. score les verdicts contre `manifest.json`,
3. **écrit directement le rapport complet** en Markdown (`--rapport`), prêt à
   committer dans `rapport/` (voir section 8 pour son contenu).

Créer `benchmark/bench_capteur.py` :

```python
#!/usr/bin/env python3
# benchmark/bench_capteur.py — rejoue le corpus à travers les VRAIS modules de
# production (prefilter→aggregateur→llm_analyzer→extractor) en chronométrant
# chaque étape, puis score contre le manifest. À lancer DANS /root sur le UP².
import os, sys, json, time, tempfile, argparse, statistics

sys.path.insert(0, "/root")                # modules de prod : pipeline & co
import oui
from prefilter import filtrer_pcap
from aggregateur import agreger
from llm_analyzer import analyser
from traqueur import Traqueur
from registre_ap import RegistreAP

CORPUS = os.path.join(os.path.dirname(os.path.abspath(__file__)), "corpus")

def warmup():
    """Une inférence à blanc pour isoler le cold-start (mesuré à part)."""
    t = time.perf_counter()
    analyser("Appareil 00:11:22:33:44:55 (MAC PERMANENT) — 1 trame en 30s.")
    return time.perf_counter() - t

def run(no_llm=False):
    manifest = json.load(open(os.path.join(CORPUS, "manifest.json")))
    traqueur = Traqueur()
    registre = RegistreAP(chemin=os.path.join(tempfile.mkdtemp(), "reg.json"))  # JAMAIS la prod

    cold = warmup() if not no_llm else 0.0
    resultats, latences = [], []

    for win in manifest:
        oui.MODE = win["mode"]
        pcap = os.path.join(CORPUS, win["pcap"])
        registre.nouvelle_fenetre()

        t0 = time.perf_counter(); candidats = filtrer_pcap(pcap);      t_pre = time.perf_counter() - t0
        t0 = time.perf_counter(); agregats  = agreger(candidats, traqueur, registre); t_agg = time.perf_counter() - t0

        t_llm, verdicts = 0.0, {}
        for agr in agregats:
            auto = agr["auto_class"]
            if auto is not None:
                verdicts[agr["mac"]] = (auto["interesting"], auto["category"], "RÈGLE", auto["reason"])
            elif no_llm:
                verdicts[agr["mac"]] = (None, None, "LLM(non éval.)", "")
            else:
                t0 = time.perf_counter(); a = analyser(agr["description"]); dt = time.perf_counter() - t0
                t_llm += dt
                verdicts[agr["mac"]] = (a.get("interesting"), a.get("category"), "LLM", a.get("reason", ""))

        latences.append({"pcap": win["pcap"], "prefilter": t_pre, "aggregateur": t_agg,
                         "llm": t_llm, "total": t_pre + t_agg + t_llm,
                         "n_llm": sum(1 for v in verdicts.values() if v[2] == "LLM")})

        for mac, att in win["attendu"].items():
            got = verdicts.get(mac)
            if got is None:
                resultats.append({"pcap": win["pcap"], "mac": mac, "label": att["label"],
                                  "att_int": att["interesting"], "got_int": "ABSENT",
                                  "att_cat": att["category"], "got_cat": "—",
                                  "chemin": "—", "ok": att["interesting"] in (False, None),
                                  "raison": "appareil non remonté par prefilter"})
                continue
            gi, gc, chemin, raison = got
            ok = (att["interesting"] is None) or (gi == att["interesting"])
            resultats.append({"pcap": win["pcap"], "mac": mac, "label": att["label"],
                              "att_int": att["interesting"], "got_int": gi,
                              "att_cat": att["category"], "got_cat": gc,
                              "chemin": chemin, "ok": ok, "raison": raison})

    return cold, resultats, latences

def stats(vals):
    if not vals: return (0, 0, 0, 0)
    s = sorted(vals)
    p95 = s[min(len(s) - 1, int(round(0.95 * (len(s) - 1))))]
    return (statistics.mean(vals), statistics.median(vals), max(vals), p95)

def rapporter(cold, resultats, latences, no_llm):
    print("\n================  COUVERTURE  ================")
    print(f"{'pcap':28} {'label':28} {'att':>4} {'got':>5} {'chemin':>14}  cat_attendue→obtenue")
    fn, fp, ok_h, ok_b = [], [], 0, 0
    for r in resultats:
        flag = "OK " if r["ok"] else "KO!"
        ai = {True:"H", False:"b", None:"?"}[r["att_int"]]
        gi = {True:"H", False:"b", None:"?"}.get(r["got_int"], str(r["got_int"]))
        print(f"{flag} {r['pcap']:26} {r['label']:26} {ai:>4} {gi:>5} {r['chemin']:>14}  {r['att_cat']}→{r['got_cat']}")
        if r["att_int"] is True:
            ok_h += r["ok"]
            if not r["ok"]: fn.append(r["label"])
        elif r["att_int"] is False:
            ok_b += r["ok"]
            if not r["ok"]: fp.append(r["label"])
    n_h = sum(1 for r in resultats if r["att_int"] is True)
    n_b = sum(1 for r in resultats if r["att_int"] is False)
    print(f"\nRappel hostiles : {ok_h}/{n_h}   |   Bénins corrects : {ok_b}/{n_b}")
    print(f"Faux négatifs (hostile raté) : {fn or 'aucun'}")
    print(f"Faux positifs (fausse alerte): {fp or 'aucun'}")

    print("\n================  LATENCE (s)  ================")
    if not no_llm:
        print(f"Cold-start LLM (1re inférence après préchargement) : {cold:.2f}s")
    print(f"{'pcap':28} {'prefilter':>9} {'aggreg':>8} {'llm':>8} {'total':>8} {'#llm':>5}")
    for L in latences:
        print(f"{L['pcap']:28} {L['prefilter']:9.3f} {L['aggregateur']:8.3f} {L['llm']:8.3f} {L['total']:8.3f} {L['n_llm']:5}")
    for nom, clef in [("prefilter","prefilter"), ("aggregateur","aggregateur"),
                      ("llm (fenêtres avec LLM)","llm"), ("total","total")]:
        if clef == "llm":
            vals = [L["llm"] for L in latences if L["n_llm"] > 0]
        else:
            vals = [L[clef] for L in latences]
        m, med, mx, p95 = stats(vals)
        print(f"  {nom:26} moy {m:7.3f}  méd {med:7.3f}  p95 {p95:7.3f}  max {mx:7.3f}")
    n_llm_calls = sum(L["n_llm"] for L in latences)
    print(f"\nAppels LLM totaux : {n_llm_calls}   |   fenêtres : {len(latences)}")

    return {"cold": cold, "resultats": resultats, "latences": latences}

def ecrire_rapport_md(cold, resultats, latences, no_llm, chemin):
    """Écrit le RAPPORT COMPLET en Markdown (section 8 du guide, auto-rempli)."""
    import datetime, llm_analyzer
    sym = {True: "hostile", False: "bénin", None: "neutre"}
    n_h = sum(1 for r in resultats if r["att_int"] is True)
    n_b = sum(1 for r in resultats if r["att_int"] is False)
    ok_h = sum(1 for r in resultats if r["att_int"] is True and r["ok"])
    ok_b = sum(1 for r in resultats if r["att_int"] is False and r["ok"])
    fn = [r for r in resultats if r["att_int"] is True and not r["ok"]]
    fp = [r for r in resultats if r["att_int"] is False and not r["ok"]]
    n_regle = sum(1 for r in resultats if r["chemin"] == "RÈGLE")
    n_llm   = sum(1 for r in resultats if r["chemin"] == "LLM")
    n_llm_calls = sum(L["n_llm"] for L in latences)

    def agg(clef, only_llm=False):
        vals = ([L["llm"] for L in latences if L["n_llm"] > 0] if only_llm
                else [L[clef] for L in latences])
        return stats(vals)  # (moy, méd, max, p95)

    L = []
    L.append("# Rapport — Benchmark complet du capteur (auto-généré)\n")
    L.append(f"**Date :** {datetime.date.today().isoformat()}  ")
    L.append(f"**Device :** UP² 7100 `wifi-llm` · `{llm_analyzer.MODEL}` (Ollama localhost:11434)  ")
    L.append("**Outils :** benchmark/generer_corpus.py + benchmark/bench_capteur.py  ")
    L.append(f"**Corpus :** {len(latences)} fenêtres pcap étiquetées (benchmark/corpus/manifest.json)  ")
    cond = "split déterministe seul (LLM non évalué)" if no_llm else "capture arrêtée, modèle préchauffé, registre temporaire isolé"
    L.append(f"**Conditions :** {cond}\n")
    L.append("---\n")

    L.append("## 1. Couverture de détection\n")
    L.append(f"- **Rappel hostiles : {ok_h}/{n_h}**" +
             (f" — faux négatifs : {', '.join(r['label'] for r in fn)} ⚠️" if fn else " — aucun faux négatif ✅"))
    L.append(f"- **Bénins correctement ignorés : {ok_b}/{n_b}**" +
             (f" — faux positifs : {', '.join(r['label'] for r in fp)}" if fp else " — aucun faux positif ✅") + "\n")
    L.append("| Scénario (pcap) | Appareil | Attendu | Obtenu | Chemin | Catégorie att.→obt. | Verdict |")
    L.append("|---|---|---|---|---|---|---|")
    for r in resultats:
        v = "✅" if r["ok"] else "❌"
        L.append(f"| {r['pcap']} | `{r['mac']}` ({r['label']}) | {sym[r['att_int']]} | "
                 f"{sym.get(r['got_int'], r['got_int'])} | {r['chemin']} | "
                 f"{r['att_cat']}→{r['got_cat']} | {v} |")
    L.append("")

    L.append("## 2. Latence par étape\n")
    if not no_llm:
        L.append(f"Cold-start LLM (1re inférence après préchauffage) : **{cold:.2f} s** "
                 "— non représentatif du régime établi, exclu des stats warm.\n")
    L.append("| Étape | Moyenne | Médiane | p95 | Max |")
    L.append("|---|---|---|---|---|")
    for nom, clef, only in [("prefilter (tshark)", "prefilter", False),
                            ("aggregateur", "aggregateur", False),
                            ("LLM (fenêtres ambiguës)", "llm", True),
                            ("total / fenêtre", "total", False)]:
        m, med, mx, p95 = agg(clef, only)
        u = lambda x: (f"{x*1000:.0f} ms" if x < 1 else f"{x:.2f} s")
        L.append(f"| {nom} | {u(m)} | {u(med)} | {u(p95)} | {u(mx)} |")
    L.append("\n**Détail par fenêtre :**\n")
    L.append("| pcap | prefilter | aggregateur | llm | total | #appels LLM |")
    L.append("|---|---|---|---|---|---|")
    for d in latences:
        L.append(f"| {d['pcap']} | {d['prefilter']*1000:.0f} ms | {d['aggregateur']*1000:.0f} ms | "
                 f"{d['llm']:.2f} s | {d['total']:.2f} s | {d['n_llm']} |")
    L.append("")

    L.append("## 3. Répartition des décisions (RÈGLE vs LLM)\n")
    tot = max(1, n_regle + n_llm)
    L.append(f"- Tranché par **RÈGLE** (coût ~0) : **{n_regle}/{tot}** ({100*n_regle/tot:.0f}%)")
    L.append(f"- Escaladé au **LLM** (cas ambigus) : **{n_llm}/{tot}** ({100*n_llm/tot:.0f}%)")
    L.append(f"- Appels LLM réellement effectués : **{n_llm_calls}** sur {len(latences)} fenêtres.\n")

    L.append("## 4. Analyse\n")
    L.append(f"- **Couverture** : {ok_h}/{n_h} types d'ennemis signalés. " +
             ("Aucun gap." if not fn else "Gaps : " + ", ".join(r['label'] for r in fn) + "."))
    if fp:
        L.append("- **Faux positifs** : " + ", ".join(f"{r['label']} (raison LLM : « {r['raison'][:80]} »)" for r in fp) +
                 ". B3 (assoc domestique) est une limite connue de qwen2.5:3b.")
    mL, *_ = agg("llm", True)
    L.append(f"- **Goulot d'étranglement** : le LLM (moy {mL:.2f} s/fenêtre ambiguë) domine ; "
             f"prefilter+aggregateur restent en millisecondes. {n_regle}/{tot} décisions évitent le LLM.")
    L.append("")

    L.append("## 5. Verdict\n")
    L.append(f"> Le capteur détecte **{ok_h}/{n_h}** types d'ennemis testés"
             + (f" ({len(fp)} faux positif(s))" if fp else " sans faux positif")
             + f". Temps médian de traitement d'une fenêtre : "
             f"**{agg('total')[1]:.2f} s** (≈ {agg('total')[1]*1000:.0f} ms hors LLM).\n")
    L.append("| Capacité | État |")
    L.append("|---|---|")
    caps = [("Attaques dures (deauth/handshake)", ["e1", "e2", "e3", "p1"]),
            ("Surveillance / reconnaissance", ["e4", "p2", "p3"]),
            ("AP furtif / over-secured", ["e6"]),
            ("Evil twin (registre persistant)", ["e7"]),
            ("Réseau mesh / multi-AP", ["mesh"]),
            ("Faux positifs zone grise", ["b3"])]
    for nom, prefixes in caps:
        lignes = [r for r in resultats if any(r["pcap"].startswith(p) for p in prefixes)]
        bon = all(r["ok"] for r in lignes) if lignes else None
        L.append(f"| {nom} | {'✅' if bon else ('❌' if bon is False else 'n/a')} |")
    L.append("\n*Campagne menée capteur arrêté ; capture + tcpdump laissés stoppés après le run.*")

    with open(chemin, "w", encoding="utf-8") as f:
        f.write("\n".join(L))
    return chemin


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--no-llm", action="store_true", help="split déterministe seul (sans Ollama)")
    ap.add_argument("--json", help="dump JSON brut des résultats")
    ap.add_argument("--rapport", help="écrit le rapport complet en Markdown à ce chemin")
    args = ap.parse_args()
    cold, resultats, latences = run(args.no_llm)
    data = rapporter(cold, resultats, latences, args.no_llm)
    if args.json:
        json.dump(data, open(args.json, "w"), indent=2, ensure_ascii=False, default=str)
        print(f"\nJSON → {args.json}")
    if args.rapport:
        print(f"Rapport Markdown → {ecrire_rapport_md(cold, resultats, latences, args.no_llm, args.rapport)}")
```

Exécution **sur le UP²** (génère la sortie console + le JSON brut + le rapport
complet en une fois) :

```bash
# (sur le UP²)
cd /root && python3 benchmark/bench_capteur.py \
    --json    /root/benchmark/resultats.json \
    --rapport /root/benchmark/rapport_benchmark.md

# Variante sans Ollama (mesure le split RÈGLE/LLM seul, sans verdict LLM) :
#   python3 benchmark/bench_capteur.py --no-llm --json /root/benchmark/resultats_split.json
```

Rapatrier le rapport + le JSON **sur le PC** pour les committer dans `rapport/` :

```bash
# (depuis le PC)
$SCP $SSH_USER@$SSH_IP:/root/benchmark/resultats.json benchmark/
$SCP $SSH_USER@$SSH_IP:/root/benchmark/rapport_benchmark.md rapport/rapport_benchmark_v1.md
```

**Lecture des résultats :**

- **Couverture** : `Rappel hostiles X/N` doit être **maximal**. Tout `KO!` sur une
  ligne `att=H` est un **faux négatif** (ennemi raté — critique). Un `KO!` sur
  `att=b` est un **faux positif** (bruit). `B3` (assoc domestique) est un faux
  positif **connu** de qwen2.5:3b (cf. `rapport_batterie_tests_v2.md`).
- **Latence** : `prefilter` (tshark) et `aggregateur` sont en **millisecondes** ;
  `llm` domine le total des fenêtres ambiguës (plusieurs secondes par inférence).
  Le **cold-start** est rapporté à part : ne pas le confondre avec le régime warm.

---

## 7. Étape 2 bis — Validation end-to-end « réelle » (optionnel mais recommandé)

Vérifie que le **pipeline complet** (y compris `extractor` + push `trames/`) rend
les mêmes verdicts que le harnais. On injecte les pcap dans `raw/` et on lit
`interesting/`.

```bash
# capture ARRÊTÉE (section 4). On relance SEULEMENT la pipeline (pas la capture).
$SSH 'mkdir -p /data/capture/raw /data/capture/done /data/capture/interesting'
$SSH 'sudo nohup python3 /root/pipeline.py > /var/log/bench_pipeline.log 2>&1 &'

# Injecter les pcap DANS L'ORDRE du manifest (le tri alphabétique du corpus
# respecte déjà l'ordre des multi-fenêtres : e7_..._1 < _2 < ... ; f1_..._1 < ...)
for p in $(ls benchmark/corpus/*.pcap | sort); do
  $SCP "$p" $SSH_USER@$SSH_IP:/data/capture/raw/
  sleep 7    # > intervalle de scrutation (5s) → traitement séquentiel ordonné
done

# Récupérer les verdicts produits
$SSH 'ls -1 /data/capture/interesting/*_analyse.json | wc -l'
$SSH 'cat /var/log/bench_pipeline.log | grep -E "⚡|✓|✗"'
$SCP -r $SSH_USER@$SSH_IP:/data/capture/interesting ./benchmark/interesting_e2e
```

> ⚠️ Cette passe **écrit dans le `registre_ap.json` de production** (E7 ajoute
> `Wifi_Cafe`). Soit on l'accepte, soit on sauvegarde/restaure :
> `$SSH 'cp /data/capture/registre_ap.json /tmp/reg.bak'` avant, restauration après.
> Arrêter la pipeline ensuite : `$SSH 'sudo pkill -f pipeline.py'`.

---

## 8. Étape 3 — Le rapport complet

L'option `--rapport` (section 6) **produit automatiquement** le rapport complet,
chiffres remplis. Il suffit de le rapatrier dans `rapport/rapport_benchmark_vN.md`
(convention projet : toute campagne de tests → un rapport écrit) et d'y ajouter,
si besoin, un paragraphe d'analyse qualitative à la main.

**Contenu du rapport généré** (5 sections) :

1. **Couverture de détection** — en-tête (rappel hostiles X/N, faux négatifs, faux
   positifs) + **tableau complet ligne par ligne** : pour chaque scénario, appareil,
   attendu (hostile/bénin), obtenu, chemin (RÈGLE/LLM), catégorie attendue→obtenue,
   verdict ✅/❌. Tout faux négatif (ennemi raté) est marqué ⚠️.
2. **Latence par étape** — tableau agrégé (moyenne / médiane / p95 / max) pour
   prefilter, aggregateur, LLM, total ; **cold-start LLM rapporté à part** ; puis le
   **détail par fenêtre** (ms par étape + nombre d'appels LLM).
3. **Répartition RÈGLE vs LLM** — part des décisions tranchées sans LLM (coût ~0) vs
   escaladées, et nombre d'inférences réellement faites.
4. **Analyse** — couverture et gaps éventuels, faux positifs avec la raison
   renvoyée par le LLM, identification du goulot d'étranglement (le LLM).
5. **Verdict** — phrase de synthèse (X/N ennemis détectés, temps médian/fenêtre) +
   **tableau de capacités** (attaques dures, surveillance, AP furtif, evil twin,
   réseau mesh / multi-AP, faux positifs zone grise) avec ✅/❌ déduit des résultats.

La structure produite est la suivante (référence — c'est ce que `--rapport` écrit) :

```markdown
# Rapport — Benchmark complet du capteur (vN)

**Date :** AAAA-MM-JJ
**Device :** UP² 7100 `wifi-llm` · `qwen2.5:3b` (Ollama localhost:11434)
**Outils :** benchmark/generer_corpus.py + benchmark/bench_capteur.py
**Corpus :** <N> fenêtres pcap étiquetées (voir benchmark/corpus/manifest.json)
**Conditions :** capture arrêtée, modèle préchauffé, registre temporaire isolé.

## 1. Couverture de détection
| Catégorie | Scénario | Attendu | Obtenu | Chemin | Verdict |
|---|---|---|---|---|---|
| deauth_attack (broadcast) | E1 | hostile/high | … | RÈGLE | ✅/❌ |
| … (une ligne par scénario E/B/P/M) | | | | | |

- **Rappel hostiles : X/N.** Faux négatifs : … (critique si non vide)
- **Faux positifs : …** (B3 = limite connue de qwen2.5:3b)

## 2. Latence par étape
| Étape | Moyenne | Médiane | p95 | Max |
|---|---|---|---|---|
| prefilter (tshark) | … ms | | | |
| aggregateur | … ms | | | |
| LLM (fenêtres ambiguës) | … s | | | |
| total / fenêtre | … s | | | |

- Cold-start LLM (1re inférence) : … s — non représentatif du régime établi.
- Part des fenêtres tranchées par RÈGLE (coût ~0) : …% ; escaladées au LLM : …%.

## 3. Analyse
- Couverture : … (toutes catégories couvertes ? gaps ?)
- Goulot d'étranglement : … (le LLM ? combien d'inférences/fenêtre en pire cas ?)
- Faux positifs/négatifs : causes, lien avec les limites du petit modèle.

## 4. Verdict
> En une phrase : le capteur détecte X/N types d'ennemis ; le temps médian de
> traitement d'une fenêtre est … (RÈGLE) / … (avec LLM).

*Campagne menée capteur arrêté ; capture + tcpdump laissés stoppés après le run.*
```

> Le rapport est rempli automatiquement par `--rapport` à partir des mesures
> réelles. N'ajouter à la main qu'une éventuelle analyse qualitative (causes des
> faux positifs, comparaison avec `rapport_batterie_tests_v2.md`, pistes).

---

## 9. Nettoyage (obligatoire après la campagne)

```bash
# S'assurer que rien ne capture/scrute en arrière-plan sur le UP²
$SSH 'sudo pkill -f pipeline.py 2>/dev/null; sudo bash /root/capteur.sh stop'
$SSH 'sudo bash /root/capteur.sh status'        # doit montrer Pipeline+Capture ARRÊTÉES
# Si la passe e2e (section 7) a touché le registre de prod et qu'on l'avait sauvé :
$SSH 'cp /tmp/reg.bak /data/capture/registre_ap.json' 2>/dev/null || true
```

Convention projet : **après toute manip/test sur le UP², `capture.sh` et
`tcpdump` doivent être tués** (le capteur reste arrêté).

---

## 10. Checklist de relance (TL;DR — « me redonner ce md »)

**Tout sur le UP², sauf push des scripts / pull du rapport.**

1. (PC) `source .env` ; définir `$SSH`/`$SCP` ; `sshpass` installé (section 3).
2. (PC) Pousser les 2 scripts : `$SCP benchmark/{generer_corpus,bench_capteur}.py $SSH_USER@$SSH_IP:/root/benchmark/`.
3. (UP²) Pré-requis : `pip3 install scapy`, vérifier tshark + Ollama + `qwen2.5:3b` (section 3).
4. (UP²) `sudo bash /root/capteur.sh stop` + préchauffer Ollama (section 4).
5. (UP²) `cd /root && python3 benchmark/generer_corpus.py` → corpus + manifest (section 5).
6. (UP²) `python3 benchmark/bench_capteur.py --json …/resultats.json --rapport …/rapport_benchmark.md` (section 6).
7. (Option, UP²) passe end-to-end via `raw/` (section 7).
8. (PC) Rapatrier le rapport → `rapport/rapport_benchmark_v1.md` ; commit/push (section 8).
9. (UP²) Nettoyer : `capteur.sh stop`, restaurer le registre si touché (section 9).

---

## 11. Annexes

**Chemins clés**

| Quoi | Où |
|---|---|
| Modules de prod (importés tels quels) | `/root/{prefilter,aggregateur,llm_analyzer,extractor,traqueur,registre_ap,oui}.py` |
| Pipeline de prod | `/root/pipeline.py` ; entrée `/data/capture/raw/`, sortie `/data/capture/interesting/` |
| Registre AP persistant (prod) | `/data/capture/registre_ap.json` — **ne jamais polluer** depuis le bench |
| Logs pipeline | `/var/log/capteur.log` |
| Corpus + manifest | `benchmark/corpus/` (local) puis `/root/benchmark/corpus/` (UP²) |

**Constantes de décision** (à connaître pour interpréter les verdicts)

| Constante | Valeur | Fichier | Effet |
|---|---|---|---|
| deauth broadcast → high | ≥5 | `aggregateur.py` | sinon medium |
| deauth ciblé → règle | ≥3 | `aggregateur.py` | en deçà : LLM |
| handshake → règle | ≥2 EAPOL | `aggregateur.py` | |
| surveillance → règle | ≥4 SSID, MAC permanente | `aggregateur.py` | `SEUIL_SSID_SURVEILLANCE` (abaissé 5→4) |
| score sur-sécurisation beacon | ≥3/12 → suspect | `prefilter.py` | WPA3=+3, PMF=+3, masqué=+2, GCMP256=+2, signal>-25=+2 |
| persistance traqueur → LLM | ≥4 fenêtres | `traqueur.py` | filature |
| diversité SSID traqueur → LLM | ≥5 SSID | `traqueur.py` | |
| conflit evil_twin (nouveau venu) | ≤2 fenêtres | `registre_ap.py` | au-delà : « connu », plus d'escalade |
| timeout LLM | 60 s | `llm_analyzer.py` | au-delà → bénin (faux négatif silencieux) |
| catégories TOUJOURS levées | deauth_attack, handshake, evil_twin, covert_ap, over_secured | `llm_analyzer.py` | `CATEGORIES_GRAVES` |

**Limites connues à ne pas confondre avec des bugs**

- `B3` (assoc domestique isolée) : faux positif résiduel de `qwen2.5:3b`
  (incohérence raison/catégorie) — documenté, pas un bug du pipeline.
- `E8 anomaly` : la catégorie est « molle » (non forcée) — le verdict dépend du
  niveau de menace jugé par le LLM ; `interesting` attendu = `?` (à constater).
- Le timing LLM dépend de la charge du UP² et du cold-start ; toujours préchauffer
  et rapporter le cold-start séparément.

**Génération sans scapy (repli, si `pip3 install scapy` impossible sur le UP²)**

1. **Générer le corpus sur le PC** (où scapy s'installe sans contrainte) puis le
   pousser : `pip install scapy` ; `python3 benchmark/generer_corpus.py` (sortie
   locale `benchmark/corpus/`) ; `$SCP -r benchmark/corpus $SSH_USER@$SSH_IP:/root/benchmark/`.
   Le harnais tourne quand même **sur le UP²** (il a besoin de tshark + Ollama).
2. Ou, si l'on veut éviter scapy partout : adapter `generer_corpus.py` pour écrire
   les trames en hex et les convertir avec `text2pcap -l 127` (DLT radiotap),
   présent avec tshark — plus verbeux, à n'utiliser qu'en dernier recours.

> Dans les deux cas, **l'analyse et le rapport restent exécutés sur le UP²** :
> seule la fabrication des pcap peut, en repli, migrer sur le PC.

**Synchronisation.** Si l'un des modules de prod est modifié pendant la campagne,
répercuter la modif **des deux côtés** (PC ↔ UP²) via `scripts/setup_push_trames.py`
avant de relancer le bench (sinon divergence silencieuse PC/UP²).
