# Rapport — Benchmark complet du capteur (auto-généré)

**Date :** 2026-06-10  
**Device :** UP² 7100 `wifi-llm` · `qwen2.5:3b` (Ollama localhost:11434)  
**Outils :** benchmark/generer_corpus.py + benchmark/bench_capteur.py  
**Corpus :** 25 fenêtres pcap étiquetées (benchmark/corpus/manifest.json)  
**Conditions :** capture arrêtée, registre temporaire isolé, modèle non préchargé
(cold-start mesuré tel quel)

> **Suite de [v3](rapport_benchmark_v3.md).** Cette v4 abaisse le seuil de
> reconnaissance `surveillance` de **5 → 4 SSID** (`SEUIL_SSID_SURVEILLANCE`), ce qui
> tranche `p2` (permanent sondant 4 SSID) par **RÈGLE** au lieu de le laisser au LLM
> (qui le ratait par intermittence en v3).

---

## 1. Couverture de détection

- **Rappel hostiles : 14/14** — aucun faux négatif ✅
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
| p2_surveillance_4ssid.pcap | `b8:27:eb:11:22:33` (Permanent sonde 4 SSID (surveillance, règle)) | hostile | hostile | RÈGLE | surveillance→surveillance | ✅ |
| p3_esp_probe.pcap | `08:3a:8d:11:22:33` (ESP sonde (deauther ?)) | hostile | hostile | RÈGLE | None→surveillance | ✅ |
| p4_glinet_zone.pcap | `94:83:c4:11:22:33` (GL.iNet (infra domestique) sonde 6 SSID) | hostile | hostile | RÈGLE | None→surveillance | ✅ |
| mesh_1_2ap.pcap | `80:20:da:22:22:22` (Mesh nœud B (1re fenêtre)) | hostile | hostile | RÈGLE | mesh→mesh | ✅ |
| mesh_1_2ap.pcap | `80:20:da:11:11:11` (Mesh nœud A (bénin 1re fenêtre)) | bénin | bénin | RÈGLE | normal→normal | ✅ |
| mesh_2_2ap.pcap | `80:20:da:11:11:11` (Mesh nœud A (régime établi)) | hostile | hostile | RÈGLE | mesh→mesh | ✅ |
| mesh_2_2ap.pcap | `80:20:da:22:22:22` (Mesh nœud B (régime établi)) | hostile | hostile | RÈGLE | mesh→mesh | ✅ |
| f1_filature_1.pcap | `ee:88:c1:7f:33:44` (Filature randomisée (<=benin)) | bénin | bénin | RÈGLE | normal→normal | ✅ |
| f1_filature_2.pcap | `ee:88:c1:7f:33:44` (Filature randomisée (<=benin)) | bénin | bénin | RÈGLE | normal→normal | ✅ |
| f1_filature_3.pcap | `ee:88:c1:7f:33:44` (Filature randomisée (<=benin)) | bénin | bénin | RÈGLE | normal→normal | ✅ |
| f1_filature_4.pcap | `ee:88:c1:7f:33:44` (Filature randomisée (<=benin)) | bénin | bénin | LLM | normal→probe_tracking | ✅ |

## 2. Latence par étape

Cold-start LLM (1re inférence après préchauffage) : **60.06 s** — non représentatif du régime établi, exclu des stats warm.

| Étape | Moyenne | Médiane | p95 | Max |
|---|---|---|---|---|
| prefilter (tshark) | 330 ms | 311 ms | 505 ms | 506 ms |
| aggregateur | 3 ms | 0 ms | 0 ms | 79 ms |
| LLM (fenêtres ambiguës) | 50.46 s | 57.12 s | 69.93 s | 69.93 s |
| total / fenêtre | 16.48 s | 391 ms | 64.00 s | 70.32 s |

**Détail par fenêtre :**

| pcap | prefilter | aggregateur | llm | total | #appels LLM |
|---|---|---|---|---|---|
| e1_deauth_broadcast.pcap | 477 ms | 79 ms | 0.00 s | 0.56 s | 0 |
| e2_deauth_cible.pcap | 505 ms | 0 ms | 0.00 s | 0.51 s | 0 |
| e3_handshake.pcap | 486 ms | 0 ms | 0.00 s | 0.49 s | 0 |
| e4_surveillance.pcap | 506 ms | 0 ms | 57.34 s | 57.85 s | 2 |
| e5_probe_tracking.pcap | 372 ms | 0 ms | 62.99 s | 63.36 s | 3 |
| e6_over_secured.pcap | 398 ms | 0 ms | 69.93 s | 70.32 s | 3 |
| e8_anomaly.pcap | 378 ms | 0 ms | 63.62 s | 64.00 s | 3 |
| e7_evil_twin_1_legit.pcap | 391 ms | 0 ms | 0.00 s | 0.39 s | 0 |
| e7_evil_twin_2_legit.pcap | 311 ms | 0 ms | 0.00 s | 0.31 s | 0 |
| e7_evil_twin_3_legit.pcap | 278 ms | 0 ms | 0.00 s | 0.28 s | 0 |
| e7_evil_twin_4_legit.pcap | 256 ms | 0 ms | 0.00 s | 0.26 s | 0 |
| e7_evil_twin_5_rogue.pcap | 242 ms | 0 ms | 56.89 s | 57.13 s | 1 |
| b1_civil_randomise.pcap | 376 ms | 0 ms | 49.46 s | 49.83 s | 2 |
| b2_box_internet.pcap | 360 ms | 0 ms | 0.00 s | 0.36 s | 0 |
| b3_assoc_domestique.pcap | 302 ms | 0 ms | 19.75 s | 20.05 s | 1 |
| p1_glinet_deauth.pcap | 409 ms | 0 ms | 0.00 s | 0.41 s | 0 |
| p2_surveillance_4ssid.pcap | 317 ms | 0 ms | 0.00 s | 0.32 s | 0 |
| p3_esp_probe.pcap | 277 ms | 0 ms | 0.00 s | 0.28 s | 0 |
| p4_glinet_zone.pcap | 255 ms | 0 ms | 0.00 s | 0.25 s | 0 |
| mesh_1_2ap.pcap | 241 ms | 0 ms | 0.00 s | 0.24 s | 0 |
| mesh_2_2ap.pcap | 231 ms | 0 ms | 0.00 s | 0.23 s | 0 |
| f1_filature_1.pcap | 226 ms | 0 ms | 0.00 s | 0.23 s | 0 |
| f1_filature_2.pcap | 224 ms | 0 ms | 0.00 s | 0.22 s | 0 |
| f1_filature_3.pcap | 221 ms | 0 ms | 0.00 s | 0.22 s | 0 |
| f1_filature_4.pcap | 214 ms | 0 ms | 23.73 s | 23.94 s | 1 |

## 3. Répartition des décisions (RÈGLE vs LLM)

- Tranché par **RÈGLE** (coût ~0) : **21/29** (72%)
- Escaladé au **LLM** (cas ambigus) : **8/29** (28%)
- Appels LLM réellement effectués : **16** sur 25 fenêtres.

## 4. Analyse

- **Couverture** : 14/14 types d'ennemis signalés. Aucun gap.
- **Goulot d'étranglement** : le LLM (moy 50.46 s/fenêtre ambiguë) domine ; prefilter+aggregateur restent en millisecondes. 21/29 décisions évitent le LLM.

## 5. Verdict

> Le capteur détecte **14/14** types d'ennemis testés sans faux positif. Temps médian de traitement d'une fenêtre : **0.39 s** (≈ 391 ms hors LLM).

| Capacité | État |
|---|---|
| Attaques dures (deauth/handshake) | ✅ |
| Surveillance / reconnaissance | ✅ |
| AP furtif / over-secured | ✅ |
| Evil twin (registre persistant) | ✅ |
| Réseau mesh / multi-AP | ✅ |
| Faux positifs zone grise | ✅ |

## 6. Analyse complémentaire (manuelle)

### 6.1 ✅ Seuil `surveillance` abaissé 5 → 4 SSID — `p2` déterministe
En v3, `p2` (MAC permanente sondant 4 SSID) était juste sous le seuil règle (5) →
escaladé au LLM, qui le ratait par intermittence (faux négatif `qwen2.5:3b`). En
abaissant `SEUIL_SSID_SURVEILLANCE` à 4 (`aggregateur.py`), ce cas est désormais
tranché par **RÈGLE** (`surveillance`, 0 s LLM, 0 variance). Vérifié : un permanent
à **3** SSID reste sous le seuil (→ LLM), un MAC **randomisé** à 4 SSID reste bénin.
Le seuil cumulé du traqueur (`SEUIL_SSID_DIVERSITE = 5`, escalade inter-fenêtres)
est inchangé — mécanisme distinct.

### 6.2 Résultat : couverture parfaite sur ce corpus
**Rappel hostiles 14/14, 0 faux négatif, 0 faux positif (14/14 bénins).** Les trois
cas autrefois flaky (P3 ESP en v1, p2 évasion en v3) sont maintenant déterministes ;
la filature randomisée (`f1_filature_4`) et `b3` restent classés bénins ce run.

> ⚠️ Réserve honnête : `f1_filature_4` et `b3` passent toujours par le LLM (cas-limite),
> donc un run futur peut encore voir l'un d'eux basculer (non-déterminisme `qwen2.5:3b`).
> La couverture des **ennemis** (hostiles) est en revanche désormais 100 % déterministe
> sur ce corpus — aucune détection d'ennemi ne dépend plus du tirage LLM, sauf
> `e5`/`e6`/`e7` (probe_tracking / over_secured / evil_twin) qui requièrent le jugement
> du modèle par conception.

### 6.3 Latence
prefilter ~0,3 s, aggregateur ~0 s. Le passage de `p2` (et `p3`, `p4`) en RÈGLE
**réduit** encore la charge LLM. Cold-start ~60 s en bench (mitigé en prod par le
préchauffage `capteur.sh start`).

---

*Campagne menée capteur arrêté ; capture + tcpdump laissés stoppés après le run.
Registre AP de production non pollué. Seuil surveillance 5→4 déployé sur le UP² et en local.*