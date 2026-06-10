#!/usr/bin/env python3
# =============================================================================
#  llm_analyzer.py — Analyse comportementale par LLM local (Ollama)
# =============================================================================
#  Rôle       : Soumet la description comportementale agrégée d'un appareil à
#               Ollama (qwen2.5:3b, localhost:11434) et parse la réponse JSON.
#               N'est appelé que pour les cas AMBIGUS non résolus par aggregateur.py.
#               Le prompt système positionne le LLM comme capteur tactique et lui
#               impose une réponse JSON stricte : interesting, threat_level,
#               category, reason.
#               Post-traitement : force interesting=True pour les catégories graves,
#               normalise threat_level si le LLM dévie du format attendu, retourne
#               interesting=False en cas de timeout (> 60 s) ou d'erreur réseau.
#
#  Entrée     : description (str) — texte comportemental produit par aggregateur.py
#  Sortie     : dict {interesting, threat_level, category, reason}
#
#  Dépend de  : Ollama tournant sur localhost:11434 avec le modèle qwen2.5:3b
#  Appelé par : pipeline.py
# =============================================================================

import requests
import json

OLLAMA_URL = "http://localhost:11434/api/generate"
MODEL = "qwen2.5:3b"

# Garde le modèle résident en mémoire entre les inférences (et après un préchargement).
# -1 = indéfiniment : évite qu'Ollama décharge le modèle après son keep_alive par
# défaut (5 min d'inactivité), ce qui re-provoquerait un cold-start > 60s → timeout
# → faux négatif silencieux sur l'appareil suivant (cf. rapport_benchmark P2/§6.2).
KEEP_ALIVE = -1

CATEGORIES_SUSPECTES = {
    "deauth_attack", "probe_tracking", "handshake",
    "over_secured", "covert_ap", "surveillance",
    "evil_twin", "anomaly", "mesh"
}

# Catégories d'attaque "dures" : nécessitent une preuve technique spécifique
# (deauth, EAPOL, BSSID usurpé, beacon furtif). qwen2.5:3b ne les attribue
# quasiment jamais à tort → filet de sécurité : toujours retenues.
# Les autres catégories ("anomaly", "probe_tracking", "surveillance",
# "over_secured") sont sur-attribuées par le petit modèle à des appareils
# civils → on ne les force PAS, on suit le threat_level réel.
CATEGORIES_GRAVES = {"deauth_attack", "handshake", "evil_twin", "covert_ap", "over_secured", "mesh"}

SYSTEM_PROMPT = """Tu es un capteur WiFi tactique embarqué. Tu reçois le résumé comportemental d'un appareil observé en 30 secondes. Ta mission : déterminer si cet appareil est potentiellement hostile, opérationnel (militaire, renseignement, attaquant) ou simplement civil banal.

RÈGLE PRINCIPALE : interesting=true signifie "valeur de renseignement ou menace réelle". Sois strict — un faux positif est aussi coûteux qu'un faux négatif.

CRITÈRES D'UN APPAREIL HOSTILE OU OPÉRATIONNEL :
- Deauthentification(s) : brouillage actif, attaque de déconnexion → deauth_attack
- Handshake WPA capturé (EAPOL) : quelqu'un intercepte les credentials → handshake
- MAC PERMANENT qui sonde plusieurs réseaux : équipement identifiable en reconnaissance → surveillance
- MAC PERMANENT qui cherche un réseau précis : appareil traçable avec historique réseau → probe_tracking
- Beacon avec WPA3+PMF+SSID masqué combinés : réseau opérationnel, pas civil → over_secured
- Plusieurs AP (BSSID différents) annonçant le MÊME SSID → evil_twin POSSIBLE. Quand tu reçois une "COMPARAISON evil-twin" entre ces AP : le BSSID le plus ANCIEN / le plus souvent vu est la référence légitime ; un NOUVEAU VENU est l'imposteur probable s'il a un signal plus fort (il "crie" pour attirer les clients), une sécurité plus faible (downgrade WPA3→WPA2/ouvert), un fabricant (OUI) ou un canal différents → category=evil_twin, threat_level medium ou high. MAIS si les AP partagent le même fabricant et la même sécurité (simple ajout d'un point d'accès / mesh d'entreprise), ce n'est PAS un evil twin → interesting=false, category=normal.

INDICE FABRICANT (champ "fabricant", issu de l'OUI) — le COMPORTEMENT prime sur la marque :
- "[équipement habituel du site]" → infrastructure connue et ATTENDUE → ne PAS traiter comme une menace sur le seul critère de la marque (un éventuel deauth/handshake reste signalé par les règles).
- "[matériel type routeur portable — suspect en zone opérationnelle]" → matériel adverse probable (capteur déposé en zone) → suspect, threat_level au moins medium.
- Module IoT (Espressif/ESP) qui DEAUTH ou SONDE → souvent un outil d'attaque bon marché (ex. deauther ESP8266) → suspect.
- Adaptateur WiFi générique en sondage actif → reconnaissance possible.
- Smartphone/ordinateur grand public (Apple, Samsung, Intel…) avec probes banales → civil.
- Pas de fabricant = MAC randomisée = protection vie privée standard → banal.

COMPORTEMENTS CIVILS BANALS (interesting=false, catégorie=normal) :
- Probes wildcard ou ciblés depuis MAC randomisé : iOS/Android/Windows en protection vie privée
- Beacons WPA2-PSK avec SSID visible : box internet standard
- Authentifications isolées sur réseaux connus

threat_level doit être : "none", "low", "medium", ou "high". Ne jamais utiliser "normal".

Réponds UNIQUEMENT en JSON valide :
{"interesting": true/false, "threat_level": "none|low|medium|high", "category": "normal|handshake|deauth_attack|probe_tracking|evil_twin|covert_ap|surveillance|over_secured|anomaly|mesh", "reason": "une phrase factuelle et précise"}

NB : la catégorie "mesh" (même SSID porté par plusieurs AP du même fabricant = réseau mesh/multi-AP, inhabituel en zone) est attribuée DÉTERMINISTE-MENT en amont — tu n'as normalement pas à la produire."""

def analyser(description: str) -> dict:
    payload = {
        "model": MODEL,
        "system": SYSTEM_PROMPT,
        "prompt": description,
        "stream": False,
        "format": "json",
        "keep_alive": KEEP_ALIVE,
        "options": {
            "temperature": 0.1,
            # Plafond de tokens (pas une cible : avec format=json, le modèle
            # s'arrête au } final). 80 tronquait le JSON sur les raisons longues
            # — typiquement evil_twin avec sa description comparative → réponse
            # coupée → parsing KO → faux négatif silencieux. 256 laisse finir.
            "num_predict": 256,
        }
    }
    try:
        r = requests.post(OLLAMA_URL, json=payload, timeout=60)
        r.raise_for_status()
        result = json.loads(r.json()["response"])
        cat = result.get("category")
        # Normalise threat_level : le LLM retourne parfois "normal" au lieu de "none"
        level = result.get("threat_level", "none")
        if level not in ("none", "low", "medium", "high"):
            level = "none"
        result["threat_level"] = level

        # interesting suit le NIVEAU DE MENACE réel jugé par le LLM, pas la
        # seule catégorie : qwen2.5:3b sur-attribue "anomaly"/"probe_tracking"
        # à des appareils civils (probes wildcard, MAC randomisé) tout en les
        # décrivant comme bénins ("pas d'activité suspecte"). Forcer
        # interesting=True sur la catégorie générait un fort taux de faux
        # positifs sur le terrain (cf. rapport v1).
        if cat in CATEGORIES_GRAVES:
            # Filet : une attaque caractérisée est toujours remontée.
            result["interesting"] = True
            if level == "none":
                result["threat_level"] = "medium"
        elif cat in CATEGORIES_SUSPECTES:
            # Catégorie "molle" : retenue seulement si le LLM annonce un
            # niveau de menace effectif (medium/high).
            result["interesting"] = level in ("medium", "high")
        else:
            result["interesting"] = False
        return result
    except requests.exceptions.Timeout:
        return {"interesting": False, "threat_level": "none", "category": "normal", "reason": "timeout LLM"}
    except Exception as e:
        return {"interesting": False, "threat_level": "none", "category": "normal", "reason": f"erreur: {e}"}


def precharger(timeout: int = 240) -> bool:
    """Préchauffe COMPLÈTEMENT le modèle au démarrage du capteur pour absorber le
    cold-start avant le trafic réel. Charger les seuls poids ne suffit pas : la 1re
    inférence paie aussi le PREFILL CPU du long SYSTEM_PROMPT (~60s, > timeout),
    alors que les suivantes réutilisent le KV-cache de ce préfixe (~20s). On fait
    donc ici une inférence à blanc COMPLÈTE (même system prompt), avec keep_alive
    permanent, afin que la 1re VRAIE inférence soit déjà chaude. Timeout généreux
    (le 1er appel est lent par nature). Retourne True si le modèle a répondu.
    Usage shell : python3 /root/llm_analyzer.py
    """
    payload = {
        "model": MODEL,
        "system": SYSTEM_PROMPT,
        "prompt": "Appareil 00:00:00:00:00:00 (MAC PERMANENT) — 1 trame en 30s.",
        "stream": False,
        "format": "json",
        "keep_alive": KEEP_ALIVE,
        "options": {"temperature": 0.1, "num_predict": 256},
    }
    try:
        r = requests.post(OLLAMA_URL, json=payload, timeout=timeout)
        r.raise_for_status()
        return True
    except Exception:
        return False


if __name__ == "__main__":
    # Lancé directement → précharge le modèle (utilisé par capteur.sh start).
    import sys
    ok = precharger()
    print(f"Modèle {MODEL} préchargé : {'OK' if ok else 'ÉCHEC'}")
    sys.exit(0 if ok else 1)
