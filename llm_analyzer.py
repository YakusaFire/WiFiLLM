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

SYSTEM_PROMPT = """Tu es un capteur WiFi tactique embarqué. Tu reçois le résumé comportemental d'un appareil observé en 30 secondes. Ta mission : déterminer si cet appareil est potentiellement hostile, opérationnel (militaire, renseignement, attaquant) ou simplement civil banal.

RÈGLE PRINCIPALE : interesting=true signifie "valeur de renseignement ou menace réelle". Sois strict — un faux positif est aussi coûteux qu'un faux négatif.

CRITÈRES D'UN APPAREIL HOSTILE OU OPÉRATIONNEL :
- Deauthentification(s) : brouillage actif, attaque de déconnexion → deauth_attack
- Handshake WPA capturé (EAPOL) : quelqu'un intercepte les credentials → handshake
- MAC PERMANENT qui sonde plusieurs réseaux : équipement identifiable en reconnaissance → surveillance
- MAC PERMANENT qui cherche un réseau précis : appareil traçable avec historique réseau → probe_tracking
- Beacon avec WPA3+PMF+SSID masqué combinés : réseau opérationnel, pas civil → over_secured
- AP imitant un réseau connu (même SSID, BSSID différent) → evil_twin

COMPORTEMENTS CIVILS BANALS (interesting=false, catégorie=normal) :
- Probes wildcard ou ciblés depuis MAC randomisé : iOS/Android/Windows en protection vie privée
- Beacons WPA2-PSK avec SSID visible : box internet standard
- Authentifications isolées sur réseaux connus

threat_level doit être : "none", "low", "medium", ou "high". Ne jamais utiliser "normal".

Réponds UNIQUEMENT en JSON valide :
{"interesting": true/false, "threat_level": "none|low|medium|high", "category": "normal|handshake|deauth_attack|probe_tracking|evil_twin|covert_ap|surveillance|over_secured|anomaly", "reason": "une phrase factuelle et précise"}"""

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
        # Normalise threat_level : le LLM retourne parfois "normal" au lieu de "none"
        level = result.get("threat_level", "none")
        if level not in ("none", "low", "medium", "high"):
            level = "none"
            result["threat_level"] = "none"
        # Force interesting selon catégorie et niveau
        if cat in CATEGORIES_SUSPECTES:
            if cat == "probe_tracking" and level == "none":
                result["interesting"] = False
            else:
                result["interesting"] = True
        else:
            result["interesting"] = False
        return result
    except requests.exceptions.Timeout:
        return {"interesting": False, "threat_level": "none", "category": "normal", "reason": "timeout LLM"}
    except Exception as e:
        return {"interesting": False, "threat_level": "none", "category": "normal", "reason": f"erreur: {e}"}
