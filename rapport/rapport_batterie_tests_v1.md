# Rapport — Batterie de tests fonctionnels + pièges (v1)

**Date :** 2026-06-04
**Device :** UP² 7100 — `wifi-llm` · `qwen2.5:3b`
**Outil :** `test_batterie.py` (scénarios synthétiques à vérité-terrain connue, frames construites en mémoire)
**Conditions :** Ollama dédié (pipeline de prod arrêté pendant le run pour éviter les timeouts).

> **Note méthodo** : un premier run avec le pipeline de prod actif a produit 6 `timeout LLM` (Ollama saturé, appels > 45 s). Résultats invalides → relancé avec Ollama dédié. Ce rapport ne contient que les verdicts du run propre. Le LLM (`temperature=0.1`) garde une légère variabilité.

---

## 1. Objectif

Exercer **toutes** les fonctionnalités (règles, traqueur, LLM, résolution OUI, modes calibration/terrain), avec des **pièges délibérés**, et répondre à : *le capteur signale-t-il tous les appareils potentiellement hostiles ?*

---

## 2. Bilan global

| Indicateur | Résultat |
|---|---|
| **Rappel hostiles** (vrais positifs) | **11 / 12** |
| Bénins correctement ignorés | 2 / 5 |
| **Faux négatif** (hostile raté) | **L2** (over-secured) |
| **Faux positifs** | **L3, M1, M3, TR1** |
| Gap connu confirmé | E1 (evil twin) |

**En clair : aucune attaque technique n'échappe au capteur, mais il sur-signale (4 fausses alertes) et rate un cas furtif.**

---

## 3. Ce qui marche (solide)

### Règles déterministes — 100 % fiables
- `R1` deauth broadcast, `R2` deauth ciblé, `R3` handshake EAPOL, `R4` surveillance (6 SSID) → tous levés correctement.
- `R5`/`R6` MAC randomisé (probes wildcard/ciblés) → correctement **ignorés**.
- **`P1` (PIÈGE réussi)** : un GL.iNet — vendor « ami » — qui émet un deauth broadcast est **quand même levé**. La classification dure passe **avant** toute logique de fabricant. ✅
- **`L5`** : Espressif qui deauth → levé par la règle. ✅

### LLM — vraies plus-values
- **`P2` (PIÈGE réussi)** : un permanent qui sonde **4 SSID** (juste sous le seuil règle de 5) échappe à la règle mais le **LLM le rattrape** (`probe_tracking`). ✅
- **`L1`** : permanent visant un SSID précis (`MINDEF_OPS_5G`) + auth → `probe_tracking`. ✅
- **`L4`** : Espressif en probes wildcard → levé (`anomaly`) — l'indice fabricant joue. ✅
- **`M4`** : GL.iNet en **mode terrain** → levé (`probe_tracking`). ✅
- **`M2`** : GL.iNet 6 SSID en terrain → `surveillance`. ✅

---

## 4. Les problèmes (à corriger)

### ❌ FN — `L2` : AP furtif / over-secured RATÉ (vrai gap)
Un beacon SSID masqué à signal très fort (-24 dBm) est classé `normal`. **Cause** : `aggregateur.py` reconstruit la description à partir des **comptes de trames** (deauth/probe/eapol/auth) et **ne transmet pas le profil de sécurité du beacon** (WPA3, PMF, SSID masqué, score de sur-sécurisation calculé par `prefilter.py`). Le LLM ne reçoit donc « rien » d'exploitable → rate.
→ **Correctif** : injecter dans la description d'agrégat les indices de `score_securite_beacon` (sécurité, SSID masqué, signal anormal).

### ⚠️ Gap confirmé — `E1` : evil twin
Deux AP au même SSID (`Wifi_Cafe`), BSSID différents. Le capteur **ne détecte pas l'evil twin** (aucune comparaison SSID↔BSSID — gap déjà documenté). Pire : les deux beacons, mal décrits, déclenchent une **hallucination** du LLM (« sonde plusieurs réseaux » alors qu'un beacon ne sonde rien) → les deux AP sont levés en `surveillance` pour une mauvaise raison.
→ Même racine que `L2` : les **beacons sont sous-décrits** au LLM. + brique `SSID→BSSID` persistante (cf. mémoire projet).

### ❌ FP — `M1` : GL.iNet « ami » levé en calibration
Un GL.iNet qui sonde 6 SSID est levé `surveillance` **même en mode calibration**. **Cause** : la règle surveillance (≥ 5 SSID) **ignore le mode** — le marquage « équipement habituel du site » n'agit que sur le chemin LLM, pas sur les règles.
→ **Correctif** (choix de politique) : en calibration, faire sauter l'escalade/le flag pour les `FABRICANTS_SITE`, ou accepter ce signal comme volontaire.

### ❌ FP — `M3` : annotation « site » insuffisante
GL.iNet en probe bénin (1 SSID) en calibration → le LLM le lève quand même en `probe_tracking`, **ignorant** l'annotation `[équipement habituel du site]` du prompt. La suggestion textuelle ne suffit pas à brider qwen2.5:3b.
→ **Correctif** : traiter `infra_connue()` de façon **déterministe** (forcer bénin dans `aggregateur.py`) plutôt que via le prompt.

### ❌ FP — `L3` : incohérence résiduelle du LLM
Assoc domestique isolée → le LLM écrit « sans signes de menace » **mais** la lève en `anomaly`. Le correctif v2 (interesting piloté par `threat_level`) a réduit ce travers sans l'éliminer : qwen attribue encore parfois un niveau medium à un appareil qu'il décrit comme bénin.
→ Inhérent au petit modèle ; prompt plus strict ou modèle plus gros.

### ◐ FP discutable — `TR1`
Téléphone randomisé **persistant** (4 fenêtres) escaladé par le traqueur, puis levé `probe_tracking`. **Réserve de conception du test** : il sondait un SSID **ciblé** (`Hotel_Lobby`), ce qui est genuinement ambigu (un appareil qui revient chercher le même réseau). Un vrai téléphone « vie privée » fait des probes *wildcard* — l'escalade serait alors mieux écartée. À rejouer avec probe wildcard.

---

## 5. Synthèse

| Capacité | État |
|---|---|
| Attaques dures (deauth, handshake) | ✅ infaillible, indépendant du vendor/mode |
| Reconnaissance multi-SSID (règle) | ✅ |
| Évasion de seuil rattrapée par LLM | ✅ |
| probe_tracking, ESP, mode terrain | ✅ |
| **AP furtif / over-secured** | ❌ raté (beacons sous-décrits) |
| **Evil twin** | ⚠️ non implémenté + hallucination sur beacons |
| **Bénins en zone grise** | ⚠️ sur-signalés (qwen + annotation site faible) |

**Priorité de correction n°1** : enrichir la description des **beacons** transmise au LLM (corrige `L2` et l'hallucination `E1`).
**Priorité n°2** : rendre `infra_connue()` déterministe en calibration (corrige `M3`, atténue `M1`).

---

*Tests : `test_batterie.py` (17 scénarios + 2 pièges multi-fenêtres). Capteur arrêté pendant le run, relancé ensuite.*
