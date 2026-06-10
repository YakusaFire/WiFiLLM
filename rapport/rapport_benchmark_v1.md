# Rapport — Benchmark complet du capteur (auto-généré)

**Date :** 2026-06-10  
**Device :** UP² 7100 `wifi-llm` · `qwen2.5:3b` (Ollama localhost:11434)  
**Outils :** benchmark/generer_corpus.py + benchmark/bench_capteur.py  
**Corpus :** 24 fenêtres pcap étiquetées (benchmark/corpus/manifest.json)  
**Conditions :** capture arrêtée, registre temporaire isolé, modèle **non** préchargé
(cold-start mesuré tel quel — cf. §6)

---

## 1. Couverture de détection

- **Rappel hostiles : 10/11** — faux négatifs : ESP sonde (deauther ?) ⚠️
- **Bénins correctement ignorés : 14/14** — aucun faux positif ✅

| Scénario (pcap) | Appareil | Attendu | Obtenu | Chemin | Catégorie att.→obt. | Verdict |
|---|---|---|---|---|---|---|
| e1_deauth_broadcast.pcap | `00:11:22:33:44:55` (Deauth broadcast) | hostile | hostile | RÈGLE | deauth_attack→deauth_attack | ✅ |
| e2_deauth_cible.pcap | `00:11:22:33:44:55` (Deauth ciblé) | hostile | hostile | RÈGLE | deauth_attack→deauth_attack | ✅ |
| e3_handshake.pcap | `00:11:22:33:44:55` (Handshake WPA) | hostile | hostile | RÈGLE | handshake→handshake | ✅ |
| e4_surveillance.pcap | `b8:27:eb:11:22:33` (Recon multi-SSID) | hostile | hostile | RÈGLE | surveillance→surveillance | ✅ |
| e5_probe_tracking.pcap | `00:11:22:33:44:55` (Tracking SSID sensible) | hostile | hostile | LLM | None→probe_tracking | ✅ |
| e6_over_secured.pcap | `00:11:22:33:44:55` (AP sur-sécurisé furtif) | hostile | hostile | LLM | None→over_secured | ✅ |
| e8_anomaly.pcap | `b8:27:eb:11:22:33` (Anomalie (auth en rafale)) | neutre | bénin | LLM | None→probe_tracking | ✅ |
| e7_evil_twin_1_legit.pcap | `80:20:da:aa:aa:aa` (AP légitime (réf)) | bénin | bénin | RÈGLE | normal→normal | ✅ |
| e7_evil_twin_2_legit.pcap | `80:20:da:aa:aa:aa` (AP légitime (réf)) | bénin | bénin | RÈGLE | normal→normal | ✅ |
| e7_evil_twin_3_legit.pcap | `80:20:da:aa:aa:aa` (AP légitime (réf)) | bénin | bénin | RÈGLE | normal→normal | ✅ |
| e7_evil_twin_4_legit.pcap | `80:20:da:aa:aa:aa` (AP légitime (réf)) | bénin | bénin | RÈGLE | normal→normal | ✅ |
| e7_evil_twin_5_rogue.pcap | `00:de:ad:be:ef:00` (Evil twin (rogue)) | hostile | hostile | LLM | evil_twin→evil_twin | ✅ |
| e7_evil_twin_5_rogue.pcap | `80:20:da:aa:aa:aa` (AP légitime (réf)) | bénin | bénin | RÈGLE | normal→normal | ✅ |
| b1_civil_randomise.pcap | `da:a1:19:7c:00:01` (iPhone vie privée) | bénin | bénin | LLM | normal→anomaly | ✅ |
| b1_civil_randomise.pcap | `c6:2b:88:40:11:02` (Android vie privée) | bénin | bénin | LLM | normal→probe_tracking | ✅ |
| b2_box_internet.pcap | `80:20:da:bb:bb:bb` (Box WPA2) | bénin | bénin | RÈGLE | normal→normal | ✅ |
| b3_assoc_domestique.pcap | `00:11:22:33:44:55` (Assoc domestique (zone grise)) | bénin | bénin | LLM | normal→probe_tracking | ✅ |
| p1_glinet_deauth.pcap | `94:83:c4:11:22:33` (Ami fait un deauth) | hostile | hostile | RÈGLE | deauth_attack→deauth_attack | ✅ |
| p2_evasion_seuil.pcap | `b8:27:eb:11:22:33` (Évasion seuil (4 SSID)) | hostile | hostile | LLM | None→probe_tracking | ✅ |
| p3_esp_probe.pcap | `08:3a:8d:11:22:33` (ESP sonde (deauther ?)) | hostile | bénin | LLM | None→module_iot | ❌ |
| m1_glinet_calib.pcap | `94:83:c4:11:22:33` (GL.iNet 6 SSID (calib)) | bénin | bénin | RÈGLE | normal→normal | ✅ |
| m2_glinet_terrain.pcap | `94:83:c4:11:22:33` (GL.iNet 6 SSID (terrain)) | hostile | hostile | RÈGLE | None→surveillance | ✅ |
| f1_filature_1.pcap | `ee:88:c1:7f:33:44` (Filature randomisée (<=benin)) | bénin | bénin | RÈGLE | normal→normal | ✅ |
| f1_filature_2.pcap | `ee:88:c1:7f:33:44` (Filature randomisée (<=benin)) | bénin | bénin | RÈGLE | normal→normal | ✅ |
| f1_filature_3.pcap | `ee:88:c1:7f:33:44` (Filature randomisée (<=benin)) | bénin | bénin | RÈGLE | normal→normal | ✅ |
| f1_filature_4.pcap | `ee:88:c1:7f:33:44` (Filature randomisée (<=benin)) | bénin | bénin | LLM | normal→probe_tracking | ✅ |

## 2. Latence par étape

Cold-start LLM (1re inférence après préchauffage) : **60.06 s** — non représentatif du régime établi, exclu des stats warm.

| Étape | Moyenne | Médiane | p95 | Max |
|---|---|---|---|---|
| prefilter (tshark) | 345 ms | 367 ms | 451 ms | 460 ms |
| aggregateur | 3 ms | 0 ms | 0 ms | 66 ms |
| LLM (fenêtres ambiguës) | 42.22 s | 46.95 s | 68.09 s | 68.09 s |
| total / fenêtre | 17.94 s | 456 ms | 65.54 s | 68.46 s |

**Détail par fenêtre :**

| pcap | prefilter | aggregateur | llm | total | #appels LLM |
|---|---|---|---|---|---|
| e1_deauth_broadcast.pcap | 435 ms | 66 ms | 0.00 s | 0.50 s | 0 |
| e2_deauth_cible.pcap | 460 ms | 0 ms | 0.00 s | 0.46 s | 0 |
| e3_handshake.pcap | 451 ms | 0 ms | 0.00 s | 0.45 s | 0 |
| e4_surveillance.pcap | 446 ms | 0 ms | 52.99 s | 53.44 s | 2 |
| e5_probe_tracking.pcap | 368 ms | 0 ms | 68.09 s | 68.46 s | 3 |
| e6_over_secured.pcap | 367 ms | 0 ms | 65.17 s | 65.54 s | 3 |
| e8_anomaly.pcap | 368 ms | 0 ms | 63.18 s | 63.54 s | 3 |
| e7_evil_twin_1_legit.pcap | 389 ms | 0 ms | 0.00 s | 0.39 s | 0 |
| e7_evil_twin_2_legit.pcap | 311 ms | 0 ms | 0.00 s | 0.31 s | 0 |
| e7_evil_twin_3_legit.pcap | 275 ms | 0 ms | 0.00 s | 0.27 s | 0 |
| e7_evil_twin_4_legit.pcap | 255 ms | 0 ms | 0.00 s | 0.26 s | 0 |
| e7_evil_twin_5_rogue.pcap | 240 ms | 0 ms | 48.38 s | 48.62 s | 1 |
| b1_civil_randomise.pcap | 373 ms | 0 ms | 45.52 s | 45.89 s | 2 |
| b2_box_internet.pcap | 388 ms | 0 ms | 0.00 s | 0.39 s | 0 |
| b3_assoc_domestique.pcap | 313 ms | 0 ms | 17.77 s | 18.08 s | 1 |
| p1_glinet_deauth.pcap | 393 ms | 0 ms | 0.00 s | 0.39 s | 0 |
| p2_evasion_seuil.pcap | 313 ms | 0 ms | 15.98 s | 16.29 s | 1 |
| p3_esp_probe.pcap | 391 ms | 0 ms | 22.06 s | 22.45 s | 1 |
| m1_glinet_calib.pcap | 389 ms | 0 ms | 0.00 s | 0.39 s | 0 |
| m2_glinet_terrain.pcap | 317 ms | 0 ms | 0.00 s | 0.32 s | 0 |
| f1_filature_1.pcap | 294 ms | 0 ms | 0.00 s | 0.29 s | 0 |
| f1_filature_2.pcap | 263 ms | 0 ms | 0.00 s | 0.26 s | 0 |
| f1_filature_3.pcap | 248 ms | 0 ms | 0.00 s | 0.25 s | 0 |
| f1_filature_4.pcap | 233 ms | 0 ms | 23.10 s | 23.34 s | 1 |

## 3. Répartition des décisions (RÈGLE vs LLM)

- Tranché par **RÈGLE** (coût ~0) : **16/26** (62%)
- Escaladé au **LLM** (cas ambigus) : **10/26** (38%)
- Appels LLM réellement effectués : **18** sur 24 fenêtres.

## 4. Analyse

- **Couverture** : 10/11 types d'ennemis signalés. Gaps : ESP sonde (deauther ?).
- **Goulot d'étranglement** : le LLM (moy 42.22 s/fenêtre ambiguë) domine ; prefilter+aggregateur restent en millisecondes. 16/26 décisions évitent le LLM.

## 5. Verdict

> Le capteur détecte **10/11** types d'ennemis testés sans faux positif. Temps médian de traitement d'une fenêtre : **0.46 s** (≈ 456 ms hors LLM).

| Capacité | État |
|---|---|
| Attaques dures (deauth/handshake) | ✅ |
| Surveillance / reconnaissance | ❌ |
| AP furtif / over-secured | ✅ |
| Evil twin (registre persistant) | ✅ |
| Modes calibration/terrain | ✅ |
| Faux positifs zone grise | ✅ |

## 6. Analyse complémentaire (manuelle)

### 6.1 Le seul raté : `P3` — ESP qui sonde (faux négatif)
Attendu : un module Espressif émettant des probes = *deauther* bon marché probable
→ suspect. **Obtenu : bénin.** Cause : `qwen2.5:3b` a renvoyé une catégorie
**`module_iot`** qui n'existe **pas** dans le contrat (`CATEGORIES_GRAVES` /
`CATEGORIES_SUSPECTES` de `llm_analyzer.py`). Le post-traitement ne reconnaissant
pas cette catégorie, il retombe sur `interesting=False` → l'appareil est écarté.
C'est une **hallucination de catégorie** du petit modèle, pas un bug du pipeline.
*Pistes :* (a) mapper toute catégorie inconnue contenant « iot/esp » vers
`anomaly`/suspect ; (b) règle déterministe « OUI Espressif + sondage actif →
suspect » dans `aggregateur.py` (ne dépend plus du LLM) ; (c) prompt plus strict
sur la liste fermée de catégories.

> ⚠️ La ligne « Surveillance / reconnaissance ❌ » du tableau de capacités (§5) est
> due **uniquement** à ce P3 : E4 (recon multi-SSID, RÈGLE) et P2 (évasion de seuil,
> rattrapé par le LLM) sont **réussis**. La reconnaissance « classique » est donc
> bien couverte ; seul le cas ESP échappe.

### 6.2 Cold-start LLM > 60 s = **timeout** (risque opérationnel réel)
La 1re inférence après démarrage a atteint **60,06 s = le timeout dur** de
`llm_analyzer.py`. Conséquence en production : **le tout premier appareil ambigu
après un (re)démarrage du capteur serait classé bénin par timeout** (faux négatif
silencieux), le temps qu'Ollama charge `qwen2.5:3b` en mémoire. *Correctif
recommandé :* préchauffer le modèle au lancement (`capteur.sh start` → une requête
à blanc, ou `OLLAMA_KEEP_ALIVE=-1` pour le garder résident). En régime établi, les
inférences retombent à **~16–27 s**.

### 6.3 Latence LLM warm = goulot d'étranglement
Hors cold-start, chaque inférence prend **~16 à 27 s** sur ce UP². Une fenêtre avec
**3 appareils ambigus** (e5, e6, e8) coûte donc **~65 s** — soit **plus que la
rotation de capture de 30 s**. En charge réelle (beaucoup d'ambigus simultanés), la
pipeline accumulerait du retard. Les RÈGLES déterministes (prefilter 0,35 s +
aggregateur ~0 s) absorbent **62 %** du flux à coût nul : c'est ce qui rend le
système viable. *Pistes si le terrain est dense :* modèle plus petit/quantifié,
plafond d'ambigus traités par fenêtre, ou batching.

### 6.4 Points forts confirmés
- **Zéro faux positif (14/14 bénins)** — y compris `B3` (assoc domestique), qui
  était l'unique faux positif du `rapport_batterie_tests_v2.md`. Le pilotage par
  `threat_level` tient ici.
- **Evil twin (E7) détecté de bout en bout** : 4 fenêtres établissent le BSSID
  légitime, la 5e fait apparaître le rogue (signal -30 vs -68, canal 11 vs 6) → le
  `RegistreAP` lève le conflit, le LLM tranche `evil_twin`. La référence légitime
  reste bénigne.
- **Attaques dures infaillibles** : deauth (broadcast/ciblé), handshake — toutes
  par RÈGLE, indépendantes du vendor (P1 : GL.iNet « ami » qui deauth = levé) et
  du LLM.
- **Modes calibration/terrain** : GL.iNet bénin au bureau (M1), hostile en zone (M2).

---

*Campagne menée capteur arrêté ; capture + tcpdump laissés stoppés après le run.
Registre AP de production non pollué (registre temporaire isolé). Corpus : 24 pcap,
benchmark/corpus/. Mesures brutes : benchmark/resultats.json.*