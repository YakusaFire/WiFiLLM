# Capteur WiFi Embarqué avec LLM Local — UP² 7100 (8 Go RAM)

---

## Architecture générale

```
Antenne WiFi USB (mode monitor)
        │
        ▼
  [Capture brute]  ◄── tshark
        │
        ▼
  [Pré-filtre]     ◄── règles BPF + Python (élimine 90% des trames)
        │
        ▼
  [LLM local]      ◄── Ollama (Qwen / Llama tournant sur l'UP²)
        │           └── "cette trame est-elle intéressante ?"
        ▼
  [Extraction .pcap intéressants]
        │
        ▼
  [Envoi distant]  ◄── MQTT / SCP / HTTP / VPN
        │
        ▼
  [Serveur de collecte / Wireshark / SIEM]
```

---

## 1. Matériel nécessaire

### L'UP² 7100 — ce qu'on a
- CPU : Intel N-series (Alder Lake-N) — architecture x86_64
- RAM : 8 Go
- iGPU Intel intégré — peut accélérer l'inférence LLM via Vulkan
- 2 interfaces réseau : une reste pour la connectivité (SSH, envoi), l'autre ou une USB pour le monitor

### Adaptateur WiFi externe (obligatoire pour le mode monitor)

L'interface WiFi interne de l'UP² n'est généralement pas fiable pour le mode monitor. Il faut une carte USB externe avec un chipset compatible :

| Chipset | Produit typique | Mode monitor | Injection | Bande |
|---|---|---|---|---|
| **Atheros AR9271** | TP-Link TL-WN722N v1 | ✅ | ✅ | 2.4 GHz |
| **MediaTek MT7612U** | Alfa AWUS036ACM | ✅ | ✅ | 2.4 + 5 GHz |
| **Ralink RT5572** | Alfa AWUS052NH | ✅ | ✅ | 2.4 + 5 GHz |
| **Realtek RTL8812AU** | Alfa AWUS036ACH | ✅ | ✅ | 2.4 + 5 GHz |

> ⚠ Le TL-WN722N v1 (chipset AR9271) est le plus simple — driver intégré au noyau Linux, zéro configuration.

### Stockage
- SSD M.2 ou eMMC interne pour l'OS + les outils
- Carte SD ou disque USB rapide pour le tampon de capture (évite d'écrire en continu sur le SSD principal)

---

## 2. Système d'exploitation

### Choix recommandé : Debian 12 (Bookworm) Server

**Pourquoi :** Ultra-léger (~300-400 Mo RAM au repos), paquets stables, parfait pour tourner en headless 24h/24.

**Alternative :** Ubuntu Server 24.04 LTS — plus de drivers pré-compilés, légèrement plus lourd.

### Installation et configuration minimale

```bash
# Mise à jour
sudo apt update && sudo apt upgrade -y

# Supprimer tout ce qui n'est pas utile
sudo apt purge --auto-remove bluetooth avahi-daemon cups snapd -y

# Désactiver l'interface graphique si présente
sudo systemctl set-default multi-user.target

# Dépendances du projet
sudo apt install -y \
    tshark tcpdump aircrack-ng iw wireless-tools \
    python3 python3-pip python3-venv \
    curl git jq rsync \
    openssh-server ufw \
    mesa-vulkan-drivers intel-media-va-driver
```

### Sécurisation SSH

```bash
sudo systemctl enable ssh --now
sudo ufw allow ssh
sudo ufw enable
```

Éditer `/etc/ssh/sshd_config` :
```
PasswordAuthentication no
PubkeyAuthentication yes
PermitRootLogin no
```

```bash
sudo systemctl restart ssh
```

---

## 3. Configuration du mode monitor WiFi

### Identifier l'interface

```bash
ip link show
# ou
iw dev
# Trouver wlan0, wlan1, etc.
```

### Passer en mode monitor (méthode propre)

```bash
sudo ip link set wlan1 down
sudo iw wlan1 set monitor none
sudo ip link set wlan1 up

# Vérifier
iw wlan1 info
# "type monitor" doit apparaître
```

### Channel hopping — script de rotation automatique

Le WiFi est fragmenté sur plusieurs canaux. Pour capturer l'ensemble du spectre, il faut sauter de canal en canal :

```bash
#!/bin/bash
# /opt/capteur/channel_hop.sh
IFACE="wlan1"
CHANNELS_24="1 2 3 4 5 6 7 8 9 10 11"
CHANNELS_5="36 40 44 48 52 56 60 64 100 104 108 112 116 120 124 128 132 136 140"

while true; do
    for ch in $CHANNELS_24 $CHANNELS_5; do
        iw "$IFACE" set channel "$ch" 2>/dev/null
        sleep 0.3
    done
done
```

```bash
chmod +x /opt/capteur/channel_hop.sh
```

---

## 4. Capture des trames

### Lancement de tshark en capture continue

```bash
mkdir -p /data/capture/raw

tshark -i wlan1 \
    -b duration:30 \
    -b filesize:20000 \
    -w /data/capture/raw/raw.pcap \
    -F pcap \
    -q
```

Options importantes :
- `-b duration:30` : nouveau fichier toutes les 30 secondes
- `-b filesize:20000` : ou dès que le fichier dépasse 20 Mo
- Cela génère des fichiers nommés `raw_00001.pcap`, `raw_00002.pcap`, etc.

### Filtrage BPF à la capture (optionnel, économise de l'espace)

Pour ne capturer que les trames de management et éviter de saturer le stockage avec des données 802.11 brutes inutiles :

```bash
tshark -i wlan1 \
    -f "type mgt or (type data subtype eapol)" \
    -w /data/capture/raw/raw.pcap \
    -b duration:30
```

---

## 5. Pré-filtrage intelligent (avant le LLM)

L'inférence LLM coûte du temps CPU. Il faut **éliminer au maximum les trames banales avant d'appeler le LLM** — typiquement 80 à 90% du trafic WiFi est des beacons et des ACK sans intérêt.

### Types de trames considérées intéressantes

| Type | Sous-type | Valeur hex | Pourquoi intéressant |
|---|---|---|---|
| Management | Association Request | 0x00 | Un appareil rejoint un réseau |
| Management | Association Response | 0x01 | Réponse de l'AP |
| Management | Probe Request | 0x04 | Un appareil cherche un réseau connu |
| Management | Deauthentication | 0x0c | Possible attaque de déauthentification |
| Management | Disassociation | 0x0a | Même chose |
| Management | Authentication | 0x0b | Début de handshake |
| Data | EAPOL | — | Handshake WPA/WPA2 (capture du hash) |

### Script Python de pré-filtrage

```python
#!/usr/bin/env python3
# /opt/capteur/prefilter.py

import subprocess
import json
import os
import sys

INTERESTING_SUBTYPES = {
    "0x0000",  # Association Request
    "0x0001",  # Association Response
    "0x0004",  # Probe Request
    "0x0008",  # Beacon (seulement si SSID inhabituel)
    "0x000a",  # Disassociation
    "0x000b",  # Authentication
    "0x000c",  # Deauthentication
}

def extract_metadata(pcap_path: str) -> list:
    """Extrait les métadonnées de chaque trame via tshark."""
    cmd = [
        "tshark", "-r", pcap_path, "-T", "json",
        "-e", "frame.number",
        "-e", "wlan.fc.type_subtype",
        "-e", "wlan.ssid",
        "-e", "wlan.bssid",
        "-e", "wlan.sa",
        "-e", "wlan.da",
        "-e", "radiotap.dbm_antsignal",
        "-e", "eapol.type",
    ]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
    if result.returncode != 0:
        return []
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError:
        return []

def is_interesting_static(frame: dict) -> bool:
    """Règles statiques rapides — pas de LLM."""
    layers = frame.get("_source", {}).get("layers", {})

    # Handshake WPA/WPA2
    if "eapol.type" in layers:
        return True

    subtype = layers.get("wlan.fc.type_subtype", [""])[0]
    if subtype in INTERESTING_SUBTYPES:
        # Ignorer les beacons génériques pour ne pas surcharger le LLM
        if subtype == "0x0008":
            ssid = layers.get("wlan.ssid", [""])[0]
            # Garder uniquement les beacons avec SSID vide (réseau caché)
            return ssid == ""
        return True

    return False

def build_summary(frame: dict) -> str:
    """Construit un résumé textuel court pour le LLM."""
    layers = frame.get("_source", {}).get("layers", {})
    return (
        f"type={layers.get('wlan.fc.type_subtype', ['?'])[0]} "
        f"ssid={layers.get('wlan.ssid', ['?'])[0]} "
        f"bssid={layers.get('wlan.bssid', ['?'])[0]} "
        f"src={layers.get('wlan.sa', ['?'])[0]} "
        f"signal={layers.get('radiotap.dbm_antsignal', ['?'])[0]}dBm "
        f"eapol={layers.get('eapol.type', ['none'])[0]}"
    )

if __name__ == "__main__":
    pcap = sys.argv[1]
    frames = extract_metadata(pcap)
    candidates = [f for f in frames if is_interesting_static(f)]
    print(json.dumps([{
        "number": f["_source"]["layers"].get("frame.number", ["?"])[0],
        "summary": build_summary(f)
    } for f in candidates]))
```

---

## 6. LLM local — détection sémantique

### Pourquoi un LLM et pas seulement des règles ?

Les règles statiques repèrent les types connus. Le LLM peut détecter :
- Des patterns inhabituels (un appareil qui scanne massivement, une anomalie de signal)
- Des SSID suspects (typosquatting, Evil Twin)
- Des comportements qui ne correspondent pas à une règle codée en dur
- Du contexte combiné (ex: déauth + probe immédiatement après = possible attaque)

### Installation d'Ollama

```bash
curl -fsSL https://ollama.com/install.sh | sh
sudo systemctl enable ollama --now

# Vérifier
ollama list
```

### Modèles recommandés pour 8 Go de RAM

Le budget RAM disponible pour le LLM est : **8 Go - ~500 Mo (OS + outils) = ~7.5 Go max**.  
En pratique, laisser 1.5 Go de marge pour les pics de capture.

**Budget LLM : 6 Go maximum.**

| Modèle | Format | RAM | Vitesse | Qualité | Usage recommandé |
|---|---|---|---|---|---|
| **SmolLM2:1.7b** | Q4_K_M | ~1.2 Go | ⚡⚡⚡ | ★★☆ | Décision binaire rapide, boucle courte |
| **Llama3.2:3b** | Q4_K_M | ~2.0 Go | ⚡⚡⚡ | ★★★ | JSON structuré fiable, orchestration |
| **Qwen2.5:3b** | Q4_K_M | ~2.2 Go | ⚡⚡⚡ | ★★★ | Meilleur 3B pour l'analyse technique |
| **Qwen2.5:7b** | Q4_K_M | ~4.5 Go | ⚡⚡☆ | ★★★★ | Analyse approfondie, contexte long |
| **DeepSeek-R1:7b** | Q4_K_M | ~4.8 Go | ⚡☆☆ | ★★★★ | Raisonnement chaîné, cas complexes |

**Recommandation par défaut : `qwen2.5:3b`** — meilleur compromis vitesse/qualité sur 8 Go.

```bash
ollama pull qwen2.5:3b
# ou si tu veux plus de puissance d'analyse
ollama pull qwen2.5:7b
```

### Activation de l'accélération Intel iGPU

L'UP² 7100 a un iGPU Intel intégré. Ollama peut le décharger via Vulkan pour accélérer la génération :

```bash
# Vérifier que les drivers Vulkan Intel sont présents
vulkaninfo --summary 2>/dev/null | grep "deviceName"

# Si nécessaire
sudo apt install -y vulkan-tools libvulkan1 mesa-vulkan-drivers

# Redémarrer Ollama — il détecte Vulkan automatiquement
sudo systemctl restart ollama
journalctl -u ollama | grep -i "vulkan\|gpu\|metal"
```

### Script d'interrogation du LLM

```python
#!/usr/bin/env python3
# /opt/capteur/llm_analyzer.py

import requests
import json

OLLAMA_URL = "http://localhost:11434/api/generate"
MODEL = "qwen2.5:3b"

SYSTEM_PROMPT = """Tu es un expert en sécurité réseau WiFi. 
On te donne le résumé d'une trame 802.11 capturée en mode monitor.
Réponds UNIQUEMENT avec du JSON valide, sans texte autour, avec ce format exact :
{
  "interesting": true,
  "confidence": 0.85,
  "category": "handshake",
  "reason": "Trame EAPOL capturée — handshake WPA2 en cours"
}

Catégories possibles : handshake, deauth_attack, probe_tracking, evil_twin, anomaly, normal
Une trame est "interesting" si elle représente une activité notable en sécurité réseau.
Les beacons standards et les trames ACK/NULL sont toujours "interesting: false"."""

def analyze_frame(frame_summary: str) -> dict:
    payload = {
        "model": MODEL,
        "system": SYSTEM_PROMPT,
        "prompt": f"Analyse cette trame WiFi : {frame_summary}",
        "stream": False,
        "format": "json",
        "options": {
            "temperature": 0.1,   # réponses déterministes
            "num_predict": 150,   # réponse courte = rapide
        }
    }
    try:
        r = requests.post(OLLAMA_URL, json=payload, timeout=15)
        r.raise_for_status()
        return json.loads(r.json()["response"])
    except Exception as e:
        return {"interesting": False, "reason": f"erreur LLM: {e}"}
```

---

## 7. Extraction des trames intéressantes en .pcap

Une fois les numéros de trames identifiés, on extrait uniquement celles-là dans un nouveau fichier .pcap :

```python
#!/usr/bin/env python3
# /opt/capteur/extractor.py

import subprocess
import os
from datetime import datetime

OUTPUT_DIR = "/data/capture/interesting"
os.makedirs(OUTPUT_DIR, exist_ok=True)

def extract_interesting_frames(source_pcap: str, frame_numbers: list, metadata: list) -> str:
    """Extrait les trames sélectionnées dans un nouveau .pcap."""
    if not frame_numbers:
        return None

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_file = os.path.join(OUTPUT_DIR, f"interesting_{timestamp}.pcap")

    # Construire le filtre tshark à partir des numéros de trames
    frame_filter = " or ".join(f"frame.number=={n}" for n in frame_numbers)

    subprocess.run([
        "tshark", "-r", source_pcap,
        "-Y", frame_filter,
        "-w", out_file
    ], check=True, capture_output=True)

    # Sauvegarder les analyses LLM dans un fichier JSON associé
    meta_file = out_file.replace(".pcap", "_analysis.json")
    import json
    with open(meta_file, "w") as f:
        json.dump(metadata, f, indent=2, ensure_ascii=False)

    return out_file
```

---

## 8. Pipeline complet — orchestration

```python
#!/usr/bin/env python3
# /opt/capteur/pipeline.py

import os
import glob
import time
import json
import logging
from prefilter import extract_metadata, is_interesting_static, build_summary
from llm_analyzer import analyze_frame
from extractor import extract_interesting_frames
from sender import send_file  # voir section suivante

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler("/var/log/capteur.log"),
        logging.StreamHandler()
    ]
)

CAPTURE_DIR = "/data/capture/raw"
PROCESSED_DIR = "/data/capture/done"
os.makedirs(PROCESSED_DIR, exist_ok=True)

def process_pcap(pcap_path: str):
    logging.info(f"Traitement : {pcap_path}")

    # 1. Extraire les métadonnées
    frames = extract_metadata(pcap_path)
    if not frames:
        return

    # 2. Pré-filtre statique
    candidates = [f for f in frames if is_interesting_static(f)]
    logging.info(f"  {len(frames)} trames → {len(candidates)} candidates après pré-filtre")

    if not candidates:
        os.rename(pcap_path, os.path.join(PROCESSED_DIR, os.path.basename(pcap_path)))
        return

    # 3. Analyse LLM pour chaque candidat
    interesting_frames = []
    for frame in candidates:
        number = frame["_source"]["layers"].get("frame.number", ["?"])[0]
        summary = build_summary(frame)
        analysis = analyze_frame(summary)

        if analysis.get("interesting", False):
            interesting_frames.append({
                "frame_number": number,
                "summary": summary,
                "analysis": analysis
            })
            logging.info(f"  ✓ Trame {number} | {analysis.get('category')} | {analysis.get('reason')}")

    # 4. Extraire en .pcap si des trames intéressantes ont été trouvées
    if interesting_frames:
        numbers = [f["frame_number"] for f in interesting_frames]
        out_pcap = extract_interesting_frames(pcap_path, numbers, interesting_frames)
        if out_pcap:
            logging.info(f"  → Envoi de {out_pcap}")
            send_file(out_pcap)

    # 5. Archiver le fichier source
    os.rename(pcap_path, os.path.join(PROCESSED_DIR, os.path.basename(pcap_path)))

def main():
    logging.info("Capteur WiFi LLM démarré")
    processed = set()

    while True:
        pcap_files = sorted(glob.glob(os.path.join(CAPTURE_DIR, "*.pcap")))
        for f in pcap_files:
            if f not in processed:
                try:
                    process_pcap(f)
                except Exception as e:
                    logging.error(f"Erreur sur {f} : {e}")
                finally:
                    processed.add(f)
        time.sleep(5)

if __name__ == "__main__":
    main()
```

---

## 9. Envoi des données à distance

### Option A — SCP / rsync (simple, sécurisé, réseau local ou VPN)

```python
# sender_scp.py
import subprocess
import os

REMOTE_USER = "collector"
REMOTE_HOST = "192.168.1.100"     # ou IP Tailscale
REMOTE_PATH = "/data/pcap_incoming/"

def send_file(local_path: str):
    subprocess.run([
        "rsync", "-az", "--remove-source-files",
        local_path,
        f"{REMOTE_USER}@{REMOTE_HOST}:{REMOTE_PATH}"
    ], check=True, timeout=60)
```

### Option B — MQTT (IoT, faible bande passante, réseau instable)

Idéal si l'UP² est connecté en 4G ou sur un réseau peu fiable.

```bash
pip install paho-mqtt
```

```python
# sender_mqtt.py
import paho.mqtt.client as mqtt
import base64, json, os

BROKER_HOST = "192.168.1.100"
BROKER_PORT = 1883
TOPIC_PCAP = "capteur/wifi/pcap"
TOPIC_META = "capteur/wifi/metadata"

def send_file(local_path: str):
    client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2)
    client.connect(BROKER_HOST, BROKER_PORT, keepalive=60)

    # Envoyer les métadonnées JSON séparément (léger)
    meta_file = local_path.replace(".pcap", "_analysis.json")
    if os.path.exists(meta_file):
        with open(meta_file) as f:
            client.publish(TOPIC_META, f.read(), qos=1)

    # Envoyer le .pcap encodé en base64
    with open(local_path, "rb") as f:
        payload = json.dumps({
            "filename": os.path.basename(local_path),
            "data": base64.b64encode(f.read()).decode()
        })
        client.publish(TOPIC_PCAP, payload, qos=1)

    client.disconnect()
```

### Option C — HTTP REST (webhook, n8n, API custom)

```python
# sender_http.py
import requests, os

API_URL = "https://ton-serveur.example.com/api/pcap/upload"
API_KEY = os.environ.get("CAPTEUR_API_KEY", "")

def send_file(local_path: str):
    with open(local_path, "rb") as f:
        r = requests.post(
            API_URL,
            headers={"Authorization": f"Bearer {API_KEY}"},
            files={"pcap": (os.path.basename(local_path), f, "application/octet-stream")},
            timeout=30
        )
    r.raise_for_status()
```

### Option D — Tailscale VPN (accès universel sans ouvrir de port)

La meilleure option si l'UP² est sur un réseau inconnu ou derrière un NAT.

```bash
# Installation
curl -fsSL https://tailscale.com/install.sh | sh
sudo tailscale up --auth-key=tskey-xxxx

# L'UP² reçoit une IP fixe dans ton réseau Tailscale (ex: 100.64.x.x)
# Depuis n'importe où : ssh user@100.64.x.x
# Et rsync marche directement via cette IP
```

---

## 10. Déploiement en services systemd

### Service 1 : channel hopping

```ini
# /etc/systemd/system/channel-hop.service
[Unit]
Description=WiFi Channel Hopping
After=network.target

[Service]
Type=simple
ExecStart=/opt/capteur/channel_hop.sh
Restart=always

[Install]
WantedBy=multi-user.target
```

### Service 2 : capture tshark

```ini
# /etc/systemd/system/wifi-capture.service
[Unit]
Description=WiFi Capture
After=channel-hop.service

[Service]
Type=simple
ExecStart=/usr/bin/tshark -i wlan1 -b duration:30 -b filesize:20000 \
    -w /data/capture/raw/raw.pcap -F pcap -q
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

### Service 3 : pipeline LLM

```ini
# /etc/systemd/system/capteur-llm.service
[Unit]
Description=Capteur WiFi LLM Pipeline
After=ollama.service wifi-capture.service

[Service]
Type=simple
User=capteur
WorkingDirectory=/opt/capteur
ExecStart=/opt/capteur/venv/bin/python pipeline.py
Restart=on-failure
RestartSec=10
EnvironmentFile=/opt/capteur/.env

[Install]
WantedBy=multi-user.target
```

```bash
# Activer tous les services
sudo systemctl daemon-reload
sudo systemctl enable --now channel-hop wifi-capture ollama capteur-llm

# Logs
journalctl -u capteur-llm -f
tail -f /var/log/capteur.log
```

---

## 11. Budget RAM — dimensionnement

| Composant | Consommation estimée |
|---|---|
| Debian 12 headless | 300 – 400 Mo |
| tshark + Python pipeline | 100 – 200 Mo |
| Ollama (daemon) | 150 Mo |
| **LLM Qwen2.5:3b** chargé | ~2 200 Mo |
| **LLM Qwen2.5:7b** chargé | ~4 500 Mo |
| Tampon système / cache | 500 Mo |
| **TOTAL avec 3b** | **~3.2 Go** ✅ (4.8 Go libres) |
| **TOTAL avec 7b** | **~5.5 Go** ✅ (2.5 Go libres) |

---

## 12. Récapitulatif des choix

| Besoin | Solution retenue |
|---|---|
| OS | Debian 12 Server headless |
| Adaptateur WiFi | Alfa AWUS036ACM (MT7612U) |
| Capture | tshark avec rotation de fichiers |
| Channel hopping | Script bash + systemd |
| Pré-filtre | Python + règles BPF |
| LLM par défaut | Qwen2.5:3b via Ollama |
| LLM haute précision | Qwen2.5:7b via Ollama |
| Accélération | Intel iGPU via Vulkan |
| Envoi réseau local | rsync / SCP |
| Envoi réseau distant | Tailscale + rsync |
| Envoi IoT / 4G | MQTT (paho) |
| Envoi webhook | HTTP REST |
| Supervision | systemd + journalctl + log fichier |
