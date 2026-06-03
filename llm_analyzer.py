#!/usr/bin/env python3

import requests
import json

OLLAMA_URL = "http://localhost:11434/api/generate"
MODEL = "qwen2.5:3b"

CATEGORIES_SUSPECTES = {
    "deauth_attack", "probe_tracking", "handshake",
    "over_secured", "covert_ap", "surveillance",
    "evil_twin", "anomaly"
}

SYSTEM_PROMPT = """Tu es un analyseur de sécurité WiFi terrain embarqué. Une trame a passé un filtre automatique. Détermine si elle mérite d'être conservée et à quel niveau de menace.

CATÉGORIES ET RÈGLES interesting :
- deauth_attack : interesting=true (attaque possible, même isolée)
- handshake : interesting=true (capture d'authentification WPA)
- over_secured : interesting=true si score élevé (WPA3+PMF+SSID masqué combinés)
- evil_twin / covert_ap / surveillance / anomaly : interesting=true
- probe_tracking : interesting=true UNIQUEMENT si le probe est CIBLÉ (SSID précis indiquant un réseau connu de l'appareil). Un wildcard probe (sans SSID) ou un probe avec MAC randomisé vers un réseau banal = interesting=false, catégorie=normal
- normal : interesting=false

CONTEXTE — profil de sécurité WiFi :
Réseau civil ordinaire : WPA2-PSK, CCMP-128, SSID visible, PMF optionnel.
Réseau suspect : WPA3-SAE + PMF obligatoire + SSID masqué + GCMP-256 combinés.

POUR LES PROBE REQUESTS — distingue précisément :
- MAC permanent + SSID précis : probablement un appareil identifiable qui cherche un réseau connu → probe_tracking, interesting=true
- MAC randomisé + SSID précis : appareil cherche un réseau connu mais se cache → probe_tracking, interesting=true, threat_level=low
- MAC randomisé + wildcard (sans SSID) : comportement normal de protection vie privée → normal, interesting=false
- Rafale de probes vers des dizaines de SSID différents : balayage actif → surveillance, interesting=true

Réponds uniquement en JSON : {"interesting": true/false, "threat_level": "none|low|medium|high", "category": "normal|handshake|deauth_attack|probe_tracking|evil_twin|covert_ap|surveillance|over_secured|anomaly", "reason": "une phrase précise"}"""

def analyser(description: str) -> dict:
    payload = {
        "model": MODEL,
        "system": SYSTEM_PROMPT,
        "prompt": description,
        "stream": False,
        "format": "json",
        "options": {
            "temperature": 0.1,
            "num_predict": 80,
        }
    }
    try:
        r = requests.post(OLLAMA_URL, json=payload, timeout=45)
        r.raise_for_status()
        result = json.loads(r.json()["response"])
        # Force interesting=True pour les catégories graves (sauf probe_tracking jugé sans menace)
        cat = result.get("category")
        level = result.get("threat_level", "none")
        if cat in CATEGORIES_SUSPECTES:
            if cat == "probe_tracking" and level == "none":
                result["interesting"] = False
            else:
                result["interesting"] = True
        return result
    except requests.exceptions.Timeout:
        return {"interesting": False, "threat_level": "none", "category": "normal", "reason": "timeout LLM"}
    except Exception as e:
        return {"interesting": False, "threat_level": "none", "category": "normal", "reason": f"erreur: {e}"}
