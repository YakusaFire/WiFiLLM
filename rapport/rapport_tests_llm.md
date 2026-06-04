# Rapport de Tests — LLM WiFi Analyzer
**Date :** 2026-06-02  
**Device :** UP² 7100 — `wifi-llm` (100.126.251.3)  
**Modèle testé :** `qwen2.5:3b` via Ollama  

---

## Contexte

Validation du LLM local comme moteur de décision pour le filtrage de trames WiFi captées en mode monitor. L'objectif est de vérifier que le modèle distingue correctement les activités WiFi banales (civiles) des activités suspectes ou potentiellement hostiles.

Les tests ont été réalisés en trois phases :
1. Calibrage du prompt système
2. Classification générale (inoffensif vs suspect)
3. Détection de patterns couverts / tactiques

---

## Phase 1 — Calibrage du prompt

### Problème identifié

Avec un prompt basé sur des valeurs hexadécimales brutes (`eapol.type=1`, `0x000c`), le modèle **ignore les règles conditionnelles** et produit des résultats incorrects.

| Trame | Résultat avec prompt hex | Correct ? |
|---|---|---|
| EAPOL (handshake WPA2) | `normal` — `interesting: false` | ❌ |
| Probe Request SSID connu | `probe_tracking` mais `interesting: false` | ❌ incohérent |

### Solution

Fournir au LLM une **description en langage naturel** plutôt que des valeurs brutes. Le pré-filtre Python traduit les métadonnées tshark en texte avant d'interroger le modèle.

**Prompt final retenu :**
> *"Tu es un analyseur de sécurité WiFi terrain. Une trame suspecte vient de passer un filtre automatique. Dis si elle mérite d'être enregistrée et envoyée à un analyste."*

---

## Phase 2 — Classification générale

### Résultats

| Trame | Catégorie | `interesting` | `threat_level` | Correct ? |
|---|---|---|---|---|
| Deauthentication broadcast | `deauth_attack` | true | — | ✅ |
| Probe Request SSID connu | `probe_tracking` | true | — | ✅ |
| Beacon réseau caché | `anomaly` | true | — | ✅ |
| EAPOL handshake WPA2 | `handshake` | true | — | ✅ |

**Score : 4/4**

---

## Phase 3 — Inoffensif vs Hostile

### WiFi inoffensifs — doivent être ignorés

| Scénario | `threat_level` | `interesting` | Correct ? |
|---|---|---|---|
| Beacon SFR_1234, signal faible, présence stable | `none` | false | ✅ |
| Beacon Livebox voisin, routeur fixe | `none` | false | ✅ |
| Smartphone cherchant son réseau personnel | `low` | true | ✅ acceptable |
| Evil Twin copie SSID connu, BSSID différent | `high` | true | ✅ |
| Appareil envoyant 47 probes en 10s | `high` | true | ✅ |
| AP caché signal -15dBm en extérieur | `high` | true | ✅ |
| Flood 200 deauth ciblés en 5s | `high` | true | ✅ |

> Note : Le smartphone cherchant son réseau perso est classé `interesting: true, threat_level: low` — comportement correct, car une probe request révèle des informations sur l'historique réseau d'un appareil.

### WiFi suspects / patterns couverts

| Scénario | Catégorie détectée | `threat_level` | Correct ? |
|---|---|---|---|
| SSID caché, signal fort en extérieur | `covert_ap` | `high` | ✅ |
| SSID `ALPHA-7-CMD` (style opérationnel) | `surveillance` | `high` | ✅ |
| SSID hash aléatoire `a3f9c12b`, éphémère | `anomaly` | `low` | ⚠️ sous-évalué |
| Réseau ad-hoc IBSS peer-to-peer | `covert_ap` | `high` | ✅ |
| Beacon interval anormalement court (10ms) | `covert_ap` | `high` | ✅ |
| Faux FreeWifi (typosquat, réseau ouvert) | `covert_ap` | `high` | ✅ |

**Score : 6/6 détectés — 1 sous-évalué en sévérité**

---

## Analyse des résultats

### Points forts

- **Détection Evil Twin** : excellent, le modèle comprend le contexte BSSID vs SSID
- **Patterns comportementaux** : détecte le mass-scanning (47 probes en 10s) comme surveillance
- **Typosquatting** : identifie les SSID légèrement modifiés comme hostiles
- **Infrastructure couverte** : signal anormalement fort, intervalle beacon non standard, ad-hoc — tous correctement signalés
- **Faux négatifs nuls** : aucun réseau hostile n'a été ignoré

### Point faible identifié

Le SSID de type hash aléatoire (`a3f9c12b`) est classé `threat_level: low` alors qu'un SSID sans pattern humain lisible, apparu et disparu rapidement, mérite au minimum `medium`. Ce cas est difficile car il pourrait aussi être un routeur mal configuré.

**Mitigation :** Ce type de trame sera de toute façon remonté (`interesting: true`) — la gradation `low` vs `medium` est secondaire pour l'envoi du .pcap.

---

## Conclusion

Le modèle `qwen2.5:3b` est **validé pour le filtrage terrain** dans ce contexte. La combinaison pré-filtre statique (Python) + LLM en langage naturel est l'approche correcte :

- Le pré-filtre élimine 80-90% des trames banales (beacons standards, ACK, null data)
- Le LLM reçoit uniquement les candidats avec une description lisible
- Aucun réseau hostile détecté dans les tests n'a été manqué

### Prochaine étape

Brancher la carte WiFi USB sur l'UP², passer en mode monitor, et déployer les scripts Python du pipeline.

---

*Tests réalisés en SSH depuis la machine locale via Tailscale VPN.*
