# Rapport — Batterie de tests fonctionnels (v2, après correctifs)

**Date :** 2026-06-04
**Device :** UP² 7100 — `wifi-llm` · `qwen2.5:3b`
**Outil :** `test_batterie.py` (17 scénarios + 2 pièges multi-fenêtres)
**Conditions :** Ollama dédié (capteur arrêté), modèle préchargé.

> Fait suite au [rapport v1](rapport_batterie_tests_v1.md) (rappel 11/12, 4 faux positifs).

---

## 1. Correctifs appliqués

| # | Correctif | Cible |
|---|---|---|
| 1 | **Enrichissement beacon** : `aggregateur.py` calcule `score_securite_beacon` et injecte le profil (SSID masqué, WPA3/PMF, signal anormal) dans la description LLM | L2, hallucination E1 |
| 2 | **`infra_connue()` déterministe** : en calibration, le matériel de site (GL.iNet/Sagemcom) est forcé bénin — SAUF attaque dure | M1, M3 |
| 3 | **`over_secured` ajouté à `CATEGORIES_GRAVES`** : un réseau sur-sécurisé (valeur de renseignement) est toujours levé | L2 |
| 4 | **Timeout LLM 45 → 60 s** : robustesse au cold-start (chargement du modèle) | P2 |

> **Note méthodo (incident).** Les premiers runs « v2 » donnaient des résultats identiques à v1. Cause : un **ancien `/tmp/aggregateur.py`** (daté du 3 juin) masquait `/opt/capteur` dans le `sys.path` du test → la batterie tournait sur du code obsolète. Shadows supprimés, code vérifié (`aggregateur.__file__ == /opt/capteur/...`), puis re-run. Les résultats ci-dessous sont sur le **vrai code déployé**.

---

## 2. Résultat global

| Indicateur | v1 | **v2** |
|---|---|---|
| **Rappel hostiles** | 11/12 | **12/12** ✅ |
| Faux négatifs (hostile raté) | L2 | **aucun** |
| Faux positifs | L3, M1, M3, TR1 | **L3** seul |
| Evil twin (gap connu) | hallucination | gap propre (plus d'hallucination) |

**Tous les appareils potentiellement hostiles sont signalés. Le bruit a été divisé par 4.**

---

## 3. Détail par correctif

### ✅ Beacon enrichi → `L2` détecté
Le beacon SSID masqué (-24 dBm) est désormais décrit au LLM avec son profil (`SSID masqué, Signal extrêmement fort, score 4/12`). Le LLM le classe `over_secured` — *« réseau opérationnel ou militaire »* — et (correctif #3) le lève. Avant : `normal`, raté.

### ✅ Infra déterministe → `M1` & `M3` corrigés
- `M1` : GL.iNet sondant 6 SSID en calibration → **bénin** (« équipement habituel du site »), alors qu'avant la règle `surveillance` le levait en ignorant le mode.
- `M3` : GL.iNet probe bénin → bénin, sans même solliciter le LLM.
- **`P1` toujours OK** : un GL.iNet qui émet un **deauth** reste levé (attaque dure non suspendue). La distinction ami/hostile ne masque jamais une attaque caractérisée.
- **Mode terrain intact** : `M2` (surveillance) et `M4` (probe_tracking) → hostiles.

### ✅ Plus d'hallucination → `E1`
Avant, les beacons sous-décrits faisaient halluciner le LLM (« sonde plusieurs réseaux » sur un simple beacon) → 2 faux positifs. Maintenant : l'AP Sagemcom est bénin (site), l'AP pirate est `normal`. **L'evil twin n'est toujours pas *détecté*** (aucune comparaison SSID↔BSSID — gap documenté), mais il ne génère plus de bruit parasite.

### ✅ Cold-start → `P2`
Avec le modèle préchargé et le timeout à 60 s, l'évasion de seuil (4 SSID, sous le seuil règle de 5) est rattrapée par le LLM (`probe_tracking`).

---

## 4. Ce qui reste

### ❌ `L3` — faux positif résiduel (qwen2.5:3b)
Une assoc domestique isolée est encore levée : le LLM **hallucine** « cherche un réseau précis (probes tracking) » alors qu'il n'y a pas de probe, et assigne un niveau medium. C'est une **limite intrinsèque du petit modèle** (incohérence raison/catégorie), que le pilotage par `threat_level` réduit sans éliminer. Pistes : prompt plus strict, ou modèle plus gros.

### ⚠️ `E1` — evil twin : gap de conception
Non détecté (par construction). Nécessite une mémoire persistante `SSID → BSSID` pour repérer un nouveau BSSID usurpant un SSID établi. *(Suivi en mémoire projet.)*

---

## 5. Verdict

> **Le capteur signale 100 % des appareils hostiles testés (12/12)** — attaques dures (deauth, handshake) toujours levées quel que soit le fabricant ou le mode, reconnaissance/évasion rattrapées par le LLM, AP sur-sécurisé désormais détecté.
> **Un seul faux positif** (assoc domestique, dû à l'incohérence résiduelle de qwen2.5:3b).
> **Une limite assumée** : la détection d'evil twin (gap documenté).

| Capacité | État v2 |
|---|---|
| Attaques dures (deauth/handshake) | ✅ infaillible, indépendant vendor/mode |
| Surveillance / reconnaissance | ✅ règle + LLM (évasion rattrapée) |
| AP furtif / over-secured | ✅ corrigé |
| Modes calibration/terrain (GL.iNet) | ✅ bénin au bureau, hostile en zone |
| Faux positifs zone grise | ◐ résiduel (L3) — limite du modèle |
| Evil twin | ❌ gap connu (à implémenter) |

---

*Tests : `test_batterie.py`. Capteur laissé arrêté après la campagne (capture + tcpdump stoppés).*
