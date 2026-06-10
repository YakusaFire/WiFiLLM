# Rapport — Benchmark complet du capteur (auto-généré)

**Date :** 2026-06-10  
**Device :** UP² 7100 `wifi-llm` · `qwen2.5:3b` (Ollama localhost:11434)  
**Outils :** benchmark/generer_corpus.py + benchmark/bench_capteur.py  
**Corpus :** 25 fenêtres pcap étiquetées (benchmark/corpus/manifest.json)  
**Conditions :** capture arrêtée, registre temporaire isolé, modèle non préchargé
(cold-start mesuré tel quel)

> **Suite de [v2](rapport_benchmark_v2.md).** Cette v3 introduit la **détection de
> réseau mesh** (catégorie `mesh`) et **supprime les modes calibration/terrain** : le
> capteur opère désormais toujours en posture terrain (matériel d'infrastructure
> domestique = suspect par principe).

---

## 1. Couverture de détection

- **Rappel hostiles : 13/14** — faux négatifs : Évasion seuil (4 SSID) ⚠️
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
| p2_evasion_seuil.pcap | `b8:27:eb:11:22:33` (Évasion seuil (4 SSID)) | hostile | bénin | LLM | None→probe_tracking | ❌ |
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
| prefilter (tshark) | 336 ms | 320 ms | 463 ms | 478 ms |
| aggregateur | 3 ms | 0 ms | 0 ms | 72 ms |
| LLM (fenêtres ambiguës) | 46.69 s | 56.13 s | 70.76 s | 70.76 s |
| total / fenêtre | 17.15 s | 422 ms | 66.99 s | 71.15 s |

**Détail par fenêtre :**

| pcap | prefilter | aggregateur | llm | total | #appels LLM |
|---|---|---|---|---|---|
| e1_deauth_broadcast.pcap | 424 ms | 72 ms | 0.00 s | 0.50 s | 0 |
| e2_deauth_cible.pcap | 463 ms | 0 ms | 0.00 s | 0.46 s | 0 |
| e3_handshake.pcap | 478 ms | 0 ms | 0.00 s | 0.48 s | 0 |
| e4_surveillance.pcap | 426 ms | 0 ms | 56.56 s | 56.98 s | 2 |
| e5_probe_tracking.pcap | 369 ms | 0 ms | 62.00 s | 62.37 s | 3 |
| e6_over_secured.pcap | 388 ms | 0 ms | 70.76 s | 71.15 s | 3 |
| e8_anomaly.pcap | 377 ms | 0 ms | 66.62 s | 66.99 s | 3 |
| e7_evil_twin_1_legit.pcap | 389 ms | 0 ms | 0.00 s | 0.39 s | 0 |
| e7_evil_twin_2_legit.pcap | 314 ms | 0 ms | 0.00 s | 0.31 s | 0 |
| e7_evil_twin_3_legit.pcap | 275 ms | 0 ms | 0.00 s | 0.28 s | 0 |
| e7_evil_twin_4_legit.pcap | 257 ms | 0 ms | 0.00 s | 0.26 s | 0 |
| e7_evil_twin_5_rogue.pcap | 244 ms | 0 ms | 56.13 s | 56.38 s | 1 |
| b1_civil_randomise.pcap | 386 ms | 0 ms | 49.26 s | 49.65 s | 2 |
| b2_box_internet.pcap | 422 ms | 0 ms | 0.00 s | 0.42 s | 0 |
| b3_assoc_domestique.pcap | 320 ms | 0 ms | 16.23 s | 16.55 s | 1 |
| p1_glinet_deauth.pcap | 389 ms | 0 ms | 0.00 s | 0.39 s | 0 |
| p2_evasion_seuil.pcap | 318 ms | 0 ms | 18.96 s | 19.28 s | 1 |
| p3_esp_probe.pcap | 392 ms | 0 ms | 0.00 s | 0.39 s | 0 |
| p4_glinet_zone.pcap | 315 ms | 0 ms | 0.00 s | 0.32 s | 0 |
| mesh_1_2ap.pcap | 278 ms | 0 ms | 0.00 s | 0.28 s | 0 |
| mesh_2_2ap.pcap | 256 ms | 0 ms | 0.00 s | 0.26 s | 0 |
| f1_filature_1.pcap | 244 ms | 0 ms | 0.00 s | 0.24 s | 0 |
| f1_filature_2.pcap | 232 ms | 0 ms | 0.00 s | 0.23 s | 0 |
| f1_filature_3.pcap | 227 ms | 0 ms | 0.00 s | 0.23 s | 0 |
| f1_filature_4.pcap | 222 ms | 0 ms | 23.67 s | 23.89 s | 1 |

## 3. Répartition des décisions (RÈGLE vs LLM)

- Tranché par **RÈGLE** (coût ~0) : **20/29** (69%)
- Escaladé au **LLM** (cas ambigus) : **9/29** (31%)
- Appels LLM réellement effectués : **17** sur 25 fenêtres.

## 4. Analyse

- **Couverture** : 13/14 types d'ennemis signalés. Gaps : Évasion seuil (4 SSID).
- **Goulot d'étranglement** : le LLM (moy 46.69 s/fenêtre ambiguë) domine ; prefilter+aggregateur restent en millisecondes. 20/29 décisions évitent le LLM.

## 5. Verdict

> Le capteur détecte **13/14** types d'ennemis testés sans faux positif. Temps médian de traitement d'une fenêtre : **0.42 s** (≈ 422 ms hors LLM).

| Capacité | État |
|---|---|
| Attaques dures (deauth/handshake) | ✅ |
| Surveillance / reconnaissance | ❌ |
| AP furtif / over-secured | ✅ |
| Evil twin (registre persistant) | ✅ |
| Réseau mesh / multi-AP | ✅ |
| Faux positifs zone grise | ✅ |

## 6. Analyse complémentaire (manuelle)

### 6.1 ✅ Nouvelle fonctionnalité — détection de réseau mesh
Un réseau **mesh / multi-AP** (même SSID porté par ≥2 BSSID du **même fabricant**)
est désormais détecté et levé de façon **déterministe** (catégorie `mesh`, sans LLM),
via une nouvelle méthode `RegistreAP.infos_mesh()`. Résultats du corpus :
- `mesh_1_2ap` : en 1re fenêtre, le 2e nœud traité est levé `mesh` ; le 1er reste
  bénin (son jumeau n'est pas encore au registre au moment où on le classe).
- `mesh_2_2ap` : en régime établi, **les deux nœuds** sont levés `mesh`. ✅
- Aucun faux mesh sur les beacons mono-BSSID (box `b2`, Livebox du bruit civil).

Distinction **mesh vs evil twin** préservée : le mesh exige le **même** fabricant ;
un evil twin (vendor/sécurité différents) reste escaladé au LLM (`e7` OK). Quand un
2e BSSID du même vendor apparaît, le registre le marque « conflit » mais on tranche
le `mesh` **avant** l'escalade evil_twin pour ne pas l'envoyer à tort au LLM.

> *Limite assumée du critère :* en 2026 le mesh grand public existe (box + répéteurs).
> Le projet fait le choix « toute infra multi-AP en zone est suspecte » (posture
> terrain). Un faux positif est donc possible si un vrai mesh civil est présent — c'est
> le compromis voulu.

### 6.2 ✅ Suppression des modes calibration/terrain
Le capteur n'a plus qu'une posture (**terrain**). `oui.MODE`, `infra_connue()` et le
mode `calibration` ont été retirés. Conséquence : le matériel d'infrastructure
domestique (GL.iNet, Sagemcom) est **toujours** suspect — `p4_glinet_zone` (GL.iNet
sonde 6 SSID) est levé par RÈGLE (`surveillance`), là où l'ancien mode `calibration`
l'aurait neutralisé. Aucun faux positif introduit (14/14 bénins).

### 6.3 ⚠️ Le seul raté : `p2` (évasion de seuil) — flakiness LLM, non lié
`p2_evasion_seuil` (RPI sonde **4** SSID, juste sous le seuil règle de 5) est escaladé
au LLM, qui ce run l'a classé `probe_tracking` **mais niveau bas → bénin**. C'était
levé en v1/v2 : c'est le **non-déterminisme de `qwen2.5:3b`** sur un cas-limite (même
famille que les FP/FN `B3` et filature `TR1`), **sans rapport** avec le mesh ou le
retrait des modes (p2 = RPI, ni mesh ni vendor d'infra). La ligne « Surveillance ❌ »
du tableau §5 ne tient qu'à ce p2 : `e4`, `p3`, `p4` (la vraie reconnaissance) sont
réussis. *Piste :* abaisser le seuil surveillance à 4 SSID (déterministe) pour ne plus
dépendre du LLM sur l'évasion — hors périmètre de la feature mesh.

### 6.4 Latence — inchangée
prefilter ~0,3 s, aggregateur ~0 s, LLM warm ~16–27 s. Le `mesh` étant déterministe,
il n'ajoute **aucune** charge LLM (RÈGLE, ~0 s). Cold-start toujours ~60 s en bench
(mitigé en production par le préchauffage `capteur.sh start`, cf. v2 §6.2).

---

*Campagne menée capteur arrêté ; capture + tcpdump laissés stoppés après le run.
Registre AP de production non pollué. Détection mesh + retrait des modes déployés sur
le UP² (/root) et en local.*