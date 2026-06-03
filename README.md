# Capteur WiFi embarqué avec analyse LLM

Système de capture et d'analyse automatique du trafic WiFi 802.11 en mode passif, déployé sur un Intel UP² 7100. Chaque trame capturée passe par un filtre déterministe puis par un LLM local (Ollama / Qwen2.5 3B) qui décide si elle mérite d'être archivée.

---

## Matériel

| Composant | Détail |
|---|---|
| Calculateur | Intel UP² 7100 — 8 Go RAM, eMMC 64 Go |
| Clé WiFi | Realtek RTL8188ETV (USB, `0bda:0179`) |
| Driver | `8188eu` (out-of-tree aircrack-ng, DKMS) |
| Réseau admin | Tailscale (IP `100.126.251.3`, nom `wifi-llm`) |
| LLM local | Ollama — modèle `qwen2.5:3b` sur `localhost:11434` |

---

## Architecture générale

```
Antenne WiFi (mode monitor)
        │
        ▼
  [capture.sh]  ──── tcpdump ───→  /data/capture/raw/raw_YYYYMMDD_HHMMSS.pcap
        │                                (rotation toutes les 30 s)
        │ channel hopping 2.4 GHz + 5 GHz (0.3 s/canal)
        │
        ▼
  [pipeline.py]  surveille /data/capture/raw/ (boucle toutes les 5 s)
        │
        ├─── [prefilter.py]  ──── tshark ──→ filtre les trames intéressantes
        │         │                           sans appel LLM
        │         │  candidats (description texte)
        │         ▼
        ├─── [llm_analyzer.py] ──→ Ollama qwen2.5:3b
        │         │                  analyse + classification
        │         │  trames jugées intéressantes
        │         ▼
        └─── [extractor.py] ──── tshark ──→ /data/capture/interesting/
                                              *.pcap  +  *_analyse.json
        │
        ▼
  pcap traité déplacé vers /data/capture/done/
```

---

## Fichiers du projet

| Fichier | Rôle |
|---|---|
| `capteur.sh` | Script de contrôle : start / stop / restart / status / logs |
| `capture.sh` | Capture brute 802.11 — mode monitor + channel hopping + tcpdump |
| `pipeline.py` | Orchestrateur : surveille les pcap et enchaîne les 3 étapes |
| `prefilter.py` | Filtre déterministe — extrait et décrit les trames suspectes |
| `llm_analyzer.py` | Interface Ollama — prompt + parsing de la réponse JSON |
| `extractor.py` | Extraction des trames retenues dans un pcap + JSON d'analyse |

---

## Détail de chaque composant

### `capteur.sh` — Contrôle du système

Script principal à utiliser sur le UP² pour démarrer ou arrêter l'ensemble.

```bash
bash /root/capteur.sh start    # Lance capture + pipeline
bash /root/capteur.sh stop     # Arrête tout proprement
bash /root/capteur.sh restart  # Redémarre
bash /root/capteur.sh status   # État des processus + stats fichiers
bash /root/capteur.sh logs     # 20 dernières lignes du log pipeline
```

Au démarrage (`start`), le script :
1. Passe l'interface `wlx64d95401ebeb` en **mode monitor** via `iw dev`
2. Crée les dossiers `/data/capture/{raw,done,interesting}` si absents
3. Purge les `.pyc` pour forcer le rechargement du code Python
4. Lance `capture.sh` et `pipeline.py` en arrière-plan avec `nohup`

---

### `capture.sh` — Capture brute 802.11

Deux processus parallèles :

**Channel hopping** (arrière-plan) : bascule l'interface sur chaque canal 2.4 GHz (1–11) puis 5 GHz (36–140 DFS inclus) toutes les 300 ms. Cela couvre l'ensemble du spectre sans rester bloqué sur un seul canal.

**tcpdump** (boucle principale) : capture toutes les trames 802.11 de type management (`type mgt`) et data (`type data`) pendant 30 secondes, puis crée un nouveau fichier horodaté. La rotation toutes les 30 s garantit que les fichiers restent petits et que la pipeline les traite rapidement.

```
/data/capture/raw/raw_20260603_123456.pcap   ← fichier en cours
/data/capture/raw/raw_20260603_123526.pcap   ← suivant (30 s plus tard)
```

Format de capture : `IEEE802_11_RADIO` (radiotap header + 802.11) — compatible Wireshark.

---

### `pipeline.py` — Orchestrateur

Boucle infinie avec un délai de 5 secondes. À chaque itération, il cherche les fichiers `.pcap` non encore traités dans `/data/capture/raw/`, les traite dans l'ordre chronologique, puis déplace chaque fichier dans `/data/capture/done/` une fois terminé.

Pour chaque fichier :
```
filtrer_pcap(pcap) → liste de candidats
    si vide → "Aucun candidat", déplace le fichier
    sinon → pour chaque candidat : analyser(description) → LLM
        si interesting=true → ajouter à la liste des intéressants
    si intéressants > 0 → extraire(pcap, intéressants) → pcap + json dans interesting/
```

Logs dans `/var/log/capteur.log`.

---

### `prefilter.py` — Filtre déterministe

Lit le pcap avec `tshark -T json -e field...` et inspecte chaque trame **sans appel réseau**. Son rôle est d'éliminer la majorité du trafic banal (beacons WPA2 standard, trames data chiffrées banales) avant d'interroger le LLM, qui est lent (~30 s/appel).

**Trames systématiquement retenues :**

| Type | Code | Raison |
|---|---|---|
| Probe Request | `0x0004` | Révèle les réseaux connus d'un appareil |
| Association Request/Response | `0x0000`, `0x0001` | Tentative de connexion à un AP |
| Authentication | `0x000b` | Échange d'authentification 802.11 |
| Deauthentication | `0x000c` | Déconnexion forcée — possible attaque |
| Disassociation | `0x000a` | Déconnexion |
| EAPOL | — | Handshake WPA2 4-way |

**Beacons (`0x0008`) retenus seulement si** le score de sécurité ≥ 3. Ce score cumule :

| Indice | Points |
|---|---|
| SSID masqué | +2 |
| WPA3-SAE | +3 |
| WPA2-Enterprise / EAP | +2 |
| GCMP-256 | +2 |
| GCMP-128 | +1 |
| PMF obligatoire (802.11w) | +3 |
| PMF activé | +1 |
| Signal > −25 dBm (antenne directionnelle probable) | +2 |
| Beacon interval non standard (< 50 ou > 200 TU) | +1 |

Un réseau domestique WPA2-PSK standard ne dépasse jamais 1–2 points. Un réseau combinant WPA3 + PMF obligatoire + SSID masqué atteint 8 points — profil atypique pour un civil.

**Descriptions enrichies pour le LLM :**

- SSID : décodé depuis l'hexadécimal tshark en UTF-8 lisible
- MAC : détection automatique si randomisé (bit locally-administered = 1 dans le premier octet)
- Probe Request ciblé : `"cherchant le réseau connu 'FreeWifi' (probe ciblé — révèle l'historique réseau)"`
- Probe Request wildcard : `"cherchant n'importe quel réseau (wildcard probe)"`

---

### `llm_analyzer.py` — Analyse par LLM

Envoie la description texte d'une trame à Ollama (`qwen2.5:3b` sur `localhost:11434`) et parse la réponse JSON.

**Catégories de sortie :**

| Catégorie | Description |
|---|---|
| `normal` | Trame banale, pas d'intérêt |
| `probe_tracking` | Appareil cherche un réseau connu — traçage possible |
| `deauth_attack` | Déauthentification suspecte — possible attaque de déconnexion |
| `handshake` | Capture d'un handshake WPA2 4-way |
| `over_secured` | Réseau avec profil de sécurité anormal pour un civil |
| `evil_twin` | Point d'accès imitant un réseau légitime |
| `covert_ap` | Point d'accès clandestin |
| `surveillance` | Balayage actif de probes ou comportement de surveillance |
| `anomaly` | Comportement 802.11 anormal non classifié |

**Logique `interesting` après réponse du LLM :**

- Catégories `deauth_attack`, `handshake`, `over_secured`, `evil_twin`, `covert_ap`, `surveillance`, `anomaly` → `interesting` forcé à `true`
- `probe_tracking` avec `threat_level=none` → `interesting` forcé à `false` (wildcard probe depuis MAC randomisé = bruit normal)
- `probe_tracking` avec `threat_level` ≥ `low` → `interesting=true` (probe ciblé depuis MAC permanent)
- En cas de timeout (> 45 s) ou d'erreur → `interesting=false`

---

### `extractor.py` — Extraction des trames retenues

Pour chaque fichier pcap contenant au moins une trame intéressante, extrait exactement les trames concernées (par numéro de frame) dans un nouveau pcap, et génère un fichier JSON d'analyse à côté.

```
/data/capture/interesting/
├── raw_20260603_125601_20260603_125656.pcap        ← trames extraites
└── raw_20260603_125601_20260603_125656_analyse.json ← rapport LLM
```

Le JSON contient pour chaque trame : le numéro, la description textuelle, les métadonnées brutes (layers tshark) et la réponse complète du LLM (`interesting`, `threat_level`, `category`, `reason`).

---

## Logs

| Fichier | Contenu |
|---|---|
| `/var/log/capteur.log` | Log principal de la pipeline (trames trouvées, résultats LLM, fichiers extraits) |
| `/var/log/capture.log` | Log de capture.sh (démarrage, mode monitor, rotations) |

Exemple de log pipeline :

```
13:00:00 Pipeline démarré
13:00:05 → raw_20260603_130000.pcap
13:00:05   12 candidat(s) → LLM
13:00:38   ✓ [low] probe_tracking — Appareil avec MAC permanent cherchant un réseau connu.
13:00:38   Aucune trame intéressante
13:00:38 → raw_20260603_130030.pcap
13:00:38   3 candidat(s) → LLM
13:01:10   ✓ [high] deauth_attack — Déauthentification broadcast depuis une adresse inconnue.
13:01:10   Extrait → raw_20260603_130030_20260603_130110.pcap
```

---

## Structure des dossiers sur le UP²

```
/root/
├── capteur.sh        ← script de contrôle
├── capture.sh        ← capture brute
├── pipeline.py       ← orchestrateur
├── prefilter.py      ← filtre déterministe
├── llm_analyzer.py   ← interface LLM
└── extractor.py      ← extraction des résultats

/data/capture/
├── raw/              ← pcap en cours de traitement (rotation 30 s)
├── done/             ← pcap traités et archivés
└── interesting/      ← pcap + JSON des captures suspectes retenues

/var/log/
├── capteur.log       ← log pipeline
└── capture.log       ← log capture
```

---

## Dépendances système (UP² — Debian 12)

```bash
apt install tcpdump tshark python3 python3-requests
# Driver WiFi out-of-tree (monitor mode) :
apt install dkms build-essential linux-headers-$(uname -r)
git clone https://github.com/aircrack-ng/rtl8188eus
cd rtl8188eus && make && make install
echo "8188eu" >> /etc/modules
echo "blacklist r8188eu" > /etc/modprobe.d/blacklist-r8188eu.conf
# LLM local :
# Installer Ollama puis : ollama pull qwen2.5:3b
```

---

## Accès distant

Le UP² est accessible via Tailscale :

```bash
ssh user@100.126.251.3   # puis : su -
```

Depuis la machine de développement, les scripts Python utilisent `paramiko` avec les identifiants stockés dans `.env` pour déployer les fichiers et exécuter des commandes à distance.
