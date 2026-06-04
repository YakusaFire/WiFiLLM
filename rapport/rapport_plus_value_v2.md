# Rapport de plus-value — Règle vs LLM (v2, après correction)

**Date :** 2026-06-04
**Device :** UP² 7100 — `wifi-llm` (192.168.101.241 / 100.126.251.3)
**Modèle :** `qwen2.5:3b` via Ollama
**Outil :** `mesure_plus_value.py` (logique de prod importée sans modification)
**Échantillon :** 25 pcap récents (Ollama dédié, pipeline de prod arrêté pendant la mesure)

> Fait suite au [rapport v1](rapport_plus_value_v1.md), qui révélait un **fort taux de faux positifs** du LLM. Cette v2 mesure l'effet du correctif.

---

## 1. Le correctif

**Problème v1** (`llm_analyzer.py`) : la logique de post-traitement forçait `interesting=true` dès que la **catégorie** était « suspecte » (dont le fourre-tout `anomaly`), **en ignorant le `threat_level` et la raison** produits par le LLM. Résultat : des téléphones civils que le LLM décrivait comme « MAC randomisé, vie privée, pas d'activité suspecte » étaient quand même remontés comme menaces.

**Correction** : le `threat_level` jugé par le LLM devient la **source de vérité** de `interesting`.

```python
CATEGORIES_GRAVES = {"deauth_attack", "handshake", "evil_twin", "covert_ap"}

if cat in CATEGORIES_GRAVES:
    result["interesting"] = True              # filet : attaque caractérisée toujours retenue
    if level == "none": result["threat_level"] = "medium"
elif cat in CATEGORIES_SUSPECTES:
    result["interesting"] = level in ("medium", "high")   # catégorie "molle" : suit le niveau réel
else:
    result["interesting"] = False
```

- Les **attaques dures** (deauth, handshake, evil twin, AP furtif) gardent leur filet de sécurité.
- Les **catégories molles** (`anomaly`, `probe_tracking`, `surveillance`, `over_secured`), que qwen2.5:3b sur-attribue, ne sont retenues que si le LLM annonce un niveau de menace **effectif** (`medium`/`high`).

---

## 2. Résultats v2

**Split décisionnel** (25 pcap, 94 décisions) :

| | Décisions | Part |
|---|---|---|
| Tranché par RÈGLE | 33 | 35,1 % |
| Escaladé au LLM | 61 | 64,9 % |

**Verdict du LLM sur les 61 cas ambigus** :

| Verdict | v1 | v2 |
|---|---|---|
| « MENACE » (`interesting=true`) | 50 | **29** |
| « banal » (`interesting=false`) | 12 | **32** |

---

## 3. Avant / après — l'effet du correctif

| Métrique | v1 (forçage) | v2 (corrigé) | Effet |
|---|---|---|---|
| Décisions « menace » | 50 | **29** | **−42 %** |
| Appareils uniques flaggés | ~10 | **5** | concentré sur les vrais |
| Téléphones randomisés « vie privée » flaggés | ~6 | **0** | ✅ faux positifs éliminés |

**Les 6 appareils civils** que le LLM décrivait lui-même comme bénins en v1 (`fa:73:52:45:6d:af`, `2e:ee:59:c6:25:8b`, `a2:8e:ef:77:10:3f`, `32:9b:71:76:c0:01`, `ce:63:b1:1f:f1:a6`, `52:f0:a1:63:00:a5`) ont **disparu** de la liste des menaces — leur `threat_level` `none`/`low` les fait désormais correctement filtrer.

### Les 5 appareils encore retenus en v2 — tous défendables

| MAC | Type | Justification LLM | Légitimité |
|---|---|---|---|
| `04:7b:cb:b9:ec:6a` | **permanent** | cherche un SSID précis (5344), fréquence de probes élevée, *potentiellement hostile* | ✅ probe_tracking réel |
| `94:83:c4:a9:34:bb` | **permanent** | probes sur plusieurs réseaux, *reconnaissance* | ✅ surveillance |
| `94:83:c4:5d:d1:01` | **permanent** | probes sur plusieurs réseaux | ✅ surveillance |
| `80:20:da:c6:b8:20` | **permanent** | probes wildcard, *surveillance sans but précis* | ◐ à surveiller |
| `ea:4e:b3:d3:d1:0b` | randomisé | sonde **persistamment** un SSID précis | ✅ probe_tracking (traçable) |

Aucun n'est un téléphone « vie privée » banal : ce sont **4 MAC permanents** (donc identifiables) en sondage, plus 1 MAC randomisé mais **persistant sur une cible précise**. C'est exactement la signature comportementale que le capteur doit lever.

---

## 4. Conclusion v2 — la plus-value du LLM, propre

| Question | v1 | v2 |
|---|---|---|
| Le LLM trie-t-il mieux que les règles ? | ❌ ~80 % de faux positifs | ✅ flags concentrés sur des signaux défendables |
| Apporte-t-il une capacité absente des règles ? | oui mais noyée | ✅ **oui, exploitable** : probe_tracking + surveillance sur MAC identifiables |

**Réponse de fond à « quelle plus-value entre capteur tout-script et capteur script+LLM » :**

- Les **règles** abattent ~35 % du flux à coût nul (élimination des MAC randomisés banals) et attrapent les attaques nettes (deauth/handshake/recon) avec une fiabilité totale.
- Le **LLM**, une fois le forçage corrigé, qualifie la **zone grise** (65 % du flux) et y lève des comportements qu'**aucune règle écrite d'avance n'exprime** : un MAC permanent qui sonde plusieurs réseaux, un appareil qui traque un SSID précis sur la durée. Un capteur tout-script aurait **jeté ces appareils en silence**.

La plus-value n'est donc **pas** « le LLM détecte plus » (sur le déterministe, les règles gagnent), mais **« le LLM transforme un détecteur à seuils figés en capteur qui qualifie l'ambigu »** — à condition de lui faire confiance sur son `threat_level` plutôt que de forcer sur la catégorie.

---

## 5. Limites & suite

- **Comparaison v1↔v2 non strictement iso-pcap** : le pipeline de prod a déplacé des fichiers entre les deux lancements, donc les fenêtres de 25 pcap se recouvrent sans être identiques (88 vs 94 décisions). L'effet mesuré reste sans ambiguïté (les mêmes MAC civils sortent de la liste), mais ce n'est pas un A/B parfaitement contrôlé.
- **`anomaly` reste à surveiller** : qwen2.5:3b l'attribue encore largement ; on s'appuie désormais sur le `threat_level` pour neutraliser ça, mais un prompt plus strict (ou un modèle plus gros) réduirait le bruit en amont.
- **`evil_twin` toujours non implémenté** (cf. mémoire projet) : la détection nécessite une mémoire persistante `SSID → BSSID`, absente aujourd'hui.
- **Déploiement prod en attente** : le correctif `llm_analyzer.py` est validé en mesure (`/tmp/mesure`) mais **pas encore déployé en prod** (`/root`) — à faire lors de la relance propre du capteur, avec `aggregateur.py`/`traqueur.py` qui manquent.

---

*Mesure réalisée en SSH (`user@192.168.101.241`), Ollama dédié (pipeline de prod arrêté).*
