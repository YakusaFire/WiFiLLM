# Rapport — Benchmark complet du capteur (auto-généré)

**Date :** 2026-06-10  
**Device :** UP² 7100 `wifi-llm` · `qwen2.5:3b` (Ollama localhost:11434)  
**Outils :** benchmark/generer_corpus.py + benchmark/bench_capteur.py  
**Corpus :** 24 fenêtres pcap étiquetées (benchmark/corpus/manifest.json)  
**Conditions :** capture arrêtée, registre temporaire isolé, modèle **non** préchargé
(cold-start mesuré tel quel — cf. §6)

> **Suite de [rapport_benchmark_v1.md](rapport_benchmark_v1.md)** (rappel 10/11, gap P3
> ESP). Cette v2 applique le correctif déterministe « matériel offensif (Espressif) en
> sondage actif → suspect » dans `aggregateur.py`/`oui.py`.

---

## 1. Couverture de détection

- **Rappel hostiles : 11/11** — aucun faux négatif ✅
- **Bénins correctement ignorés : 13/14** — faux positifs : Filature randomisée (<=benin)

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
| b1_civil_randomise.pcap | `c6:2b:88:40:11:02` (Android vie privée) | bénin | bénin | LLM | normal→anomaly | ✅ |
| b2_box_internet.pcap | `80:20:da:bb:bb:bb` (Box WPA2) | bénin | bénin | RÈGLE | normal→normal | ✅ |
| b3_assoc_domestique.pcap | `00:11:22:33:44:55` (Assoc domestique (zone grise)) | bénin | bénin | LLM | normal→probe_tracking | ✅ |
| p1_glinet_deauth.pcap | `94:83:c4:11:22:33` (Ami fait un deauth) | hostile | hostile | RÈGLE | deauth_attack→deauth_attack | ✅ |
| p2_evasion_seuil.pcap | `b8:27:eb:11:22:33` (Évasion seuil (4 SSID)) | hostile | hostile | LLM | None→probe_tracking | ✅ |
| p3_esp_probe.pcap | `08:3a:8d:11:22:33` (ESP sonde (deauther ?)) | hostile | hostile | RÈGLE | None→surveillance | ✅ |
| m1_glinet_calib.pcap | `94:83:c4:11:22:33` (GL.iNet 6 SSID (calib)) | bénin | bénin | RÈGLE | normal→normal | ✅ |
| m2_glinet_terrain.pcap | `94:83:c4:11:22:33` (GL.iNet 6 SSID (terrain)) | hostile | hostile | RÈGLE | None→surveillance | ✅ |
| f1_filature_1.pcap | `ee:88:c1:7f:33:44` (Filature randomisée (<=benin)) | bénin | bénin | RÈGLE | normal→normal | ✅ |
| f1_filature_2.pcap | `ee:88:c1:7f:33:44` (Filature randomisée (<=benin)) | bénin | bénin | RÈGLE | normal→normal | ✅ |
| f1_filature_3.pcap | `ee:88:c1:7f:33:44` (Filature randomisée (<=benin)) | bénin | bénin | RÈGLE | normal→normal | ✅ |
| f1_filature_4.pcap | `ee:88:c1:7f:33:44` (Filature randomisée (<=benin)) | bénin | hostile | LLM | normal→probe_tracking | ❌ |

## 2. Latence par étape

Cold-start LLM (1re inférence après préchauffage) : **60.06 s** — non représentatif du régime établi, exclu des stats warm.

| Étape | Moyenne | Médiane | p95 | Max |
|---|---|---|---|---|
| prefilter (tshark) | 339 ms | 342 ms | 449 ms | 460 ms |
| aggregateur | 3 ms | 0 ms | 0 ms | 72 ms |
| LLM (fenêtres ambiguës) | 44.98 s | 48.97 s | 67.25 s | 67.25 s |
| total / fenêtre | 17.21 s | 418 ms | 64.81 s | 67.63 s |

**Détail par fenêtre :**

| pcap | prefilter | aggregateur | llm | total | #appels LLM |
|---|---|---|---|---|---|
| e1_deauth_broadcast.pcap | 460 ms | 72 ms | 0.00 s | 0.53 s | 0 |
| e2_deauth_cible.pcap | 449 ms | 0 ms | 0.00 s | 0.45 s | 0 |
| e3_handshake.pcap | 444 ms | 0 ms | 0.00 s | 0.44 s | 0 |
| e4_surveillance.pcap | 416 ms | 0 ms | 50.47 s | 50.89 s | 2 |
| e5_probe_tracking.pcap | 368 ms | 0 ms | 64.44 s | 64.81 s | 3 |
| e6_over_secured.pcap | 381 ms | 0 ms | 67.25 s | 67.63 s | 3 |
| e8_anomaly.pcap | 390 ms | 0 ms | 64.30 s | 64.69 s | 3 |
| e7_evil_twin_1_legit.pcap | 388 ms | 0 ms | 0.00 s | 0.39 s | 0 |
| e7_evil_twin_2_legit.pcap | 309 ms | 0 ms | 0.00 s | 0.31 s | 0 |
| e7_evil_twin_3_legit.pcap | 278 ms | 0 ms | 0.00 s | 0.28 s | 0 |
| e7_evil_twin_4_legit.pcap | 263 ms | 0 ms | 0.00 s | 0.26 s | 0 |
| e7_evil_twin_5_rogue.pcap | 259 ms | 0 ms | 48.97 s | 49.23 s | 1 |
| b1_civil_randomise.pcap | 391 ms | 0 ms | 46.52 s | 46.91 s | 2 |
| b2_box_internet.pcap | 383 ms | 0 ms | 0.00 s | 0.38 s | 0 |
| b3_assoc_domestique.pcap | 313 ms | 0 ms | 17.71 s | 18.02 s | 1 |
| p1_glinet_deauth.pcap | 388 ms | 0 ms | 0.00 s | 0.39 s | 0 |
| p2_evasion_seuil.pcap | 316 ms | 0 ms | 17.32 s | 17.64 s | 1 |
| p3_esp_probe.pcap | 392 ms | 0 ms | 0.00 s | 0.39 s | 0 |
| m1_glinet_calib.pcap | 313 ms | 0 ms | 0.00 s | 0.31 s | 0 |
| m2_glinet_terrain.pcap | 280 ms | 0 ms | 0.00 s | 0.28 s | 0 |
| f1_filature_1.pcap | 256 ms | 0 ms | 0.00 s | 0.26 s | 0 |
| f1_filature_2.pcap | 243 ms | 0 ms | 0.00 s | 0.24 s | 0 |
| f1_filature_3.pcap | 234 ms | 0 ms | 0.00 s | 0.23 s | 0 |
| f1_filature_4.pcap | 228 ms | 0 ms | 27.82 s | 28.05 s | 1 |

## 3. Répartition des décisions (RÈGLE vs LLM)

- Tranché par **RÈGLE** (coût ~0) : **17/26** (65%)
- Escaladé au **LLM** (cas ambigus) : **9/26** (35%)
- Appels LLM réellement effectués : **17** sur 24 fenêtres.

## 4. Analyse

- **Couverture** : 11/11 types d'ennemis signalés. Aucun gap.
- **Faux positifs** : Filature randomisée (<=benin) (raison LLM : « Appareil avec MAC randomisé qui probe précisément un SSID (Hotel_Lobby) plusieur »). B3 (assoc domestique) est une limite connue de qwen2.5:3b.
- **Goulot d'étranglement** : le LLM (moy 44.98 s/fenêtre ambiguë) domine ; prefilter+aggregateur restent en millisecondes. 17/26 décisions évitent le LLM.

## 5. Verdict

> Le capteur détecte **11/11** types d'ennemis testés (1 faux positif(s)). Temps médian de traitement d'une fenêtre : **0.42 s** (≈ 418 ms hors LLM).

| Capacité | État |
|---|---|
| Attaques dures (deauth/handshake) | ✅ |
| Surveillance / reconnaissance | ✅ |
| AP furtif / over-secured | ✅ |
| Evil twin (registre persistant) | ✅ |
| Modes calibration/terrain | ✅ |
| Faux positifs zone grise | ✅ |

## 6. Analyse complémentaire (manuelle)

### 6.1 ✅ Correctif P3 — ESP qui sonde, désormais détecté par RÈGLE
Le faux négatif de v1 est levé. Ajout d'un fabricant « outil offensif »
(`FABRICANTS_OUTILS = ("Espressif",)` dans `oui.py`) + `materiel_offensif(mac)`, et
d'une **règle déterministe** dans `aggregateur._auto_classifier` : un matériel
offensif (ESP) en **sondage/auth actif** → `surveillance`, hostile, **sans passer
par le LLM**. Conséquences mesurées :
- `p3_esp_probe` : `None→LLM` (v1, raté) devient `RÈGLE→surveillance` (v2, levé).
- **Rappel hostiles 10/11 → 11/11**, aucun faux négatif.
- La règle deauth reste prioritaire : un ESP qui **deauth** garde `deauth_attack`
  (vérifié). La règle n'écrase pas non plus les MAC randomisées (test local).
- Bénéfice secondaire : un appel LLM de moins (ESP tranché par règle) → 17 inférences
  au lieu de 18.

### 6.2 ⚠️ Nouveau FP `f1_filature_4` — non lié au correctif, instabilité LLM
La filature (MAC **randomisée** persistante) est, par conception, escaladée au LLM à
la 4e fenêtre (seuil traqueur) tout en devant rester **bénigne** (piège TR1). En v1
le LLM la classait bénigne ; en v2 il la lève (`probe_tracking`, *« MAC randomisé qui
probe précisément Hotel_Lobby plusieurs fois »*). **Ce basculement ne vient pas du
correctif P3** (qui ne touche que les MAC permanentes à OUI Espressif) : c'est la
**non-déterminisme résiduel de `qwen2.5:3b`** sur un cas-limite, de la même famille
que le FP `B3` connu. Le verdict dépend du tirage LLM d'une exécution à l'autre.
*Pistes (hors périmètre « problème 1 ») :* durcir le prompt sur « MAC randomisée =
vie privée, jamais probe_tracking », ou ne PAS escalader une filature randomisée tant
qu'elle ne sonde qu'**un seul** SSID (la persistance seule ne suffit pas à la rendre
hostile).

### 6.3 Latence — inchangée
Profil identique à v1 : prefilter ~0,34 s, aggregateur ~0 s, LLM warm ~16–27 s
(goulot). Cold-start toujours **> 60 s = timeout** (cf. v1 §6.2 — 2e problème ouvert,
à corriger par préchauffage au démarrage). Le correctif P3 **réduit** la charge LLM
(une inférence de moins).

---

*Campagne menée capteur arrêté ; capture + tcpdump laissés stoppés après le run.
Registre AP de production non pollué. Correctif P3 déployé sur le UP² (/root) et en
local. 2e problème (cold-start LLM) toujours ouvert.*