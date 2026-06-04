# Rapport de plus-value — Règle vs LLM (v1, état initial)

**Date :** 2026-06-04
**Device :** UP² 7100 — `wifi-llm` (192.168.101.241 / 100.126.251.3)
**Modèle :** `qwen2.5:3b` via Ollama
**Outil de mesure :** `mesure_plus_value.py` (rejoue les pcap réels à travers `prefilter → aggregateur → traqueur`, logique de prod inchangée)
**Échantillons :** 500 pcap (split déterministe) + 25 pcap (verdict LLM complet)

> **Statut : constat critique, pas une validation.** Cette v1 mesure le système *tel qu'il était configuré* et révèle un **fort taux de faux positifs du LLM**. Le correctif et la re-mesure font l'objet du rapport v2.

---

## 1. Objectif

Quantifier l'apport réel du LLM par rapport à un capteur qui ne fonctionnerait qu'avec des règles déterministes, en répondant à deux questions :

1. **Split décisionnel** — quelle part des appareils est tranchée par règle (`aggregateur.py`) vs escaladée au LLM ?
2. **Plus-value** — combien de menaces tombent dans la zone ambiguë, invisible à un capteur tout-script ?

---

## 2. Split décisionnel (déterministe)

Mesure 100 % reproductible (ni LLM ni aléatoire).

| Source | Décisions | Tranché par RÈGLE | Escaladé au LLM |
|---|---|---|---|
| **500 pcap** (~4 h 10 de capture) | 1369 | **38 %** | **62 %** |
| **25 pcap** (~12 min 30) | 88 | **29,5 %** | **70,5 %** |

- Dans l'échantillon de 25 pcap : **0 attaque nette** tranchée par règle (pas de deauth/handshake/recon) → les 26 décisions « règle » sont **toutes des appareils civils écartés** (MAC randomisé, probes de protection de vie privée).
- **Constat majeur :** sur le terrain réel, le LLM ne joue **pas** un rôle de filet rare. Il porte **62-70 % des décisions**. La part « tranchée à coût nul » par les règles est minoritaire (un capteur tout-LLM n'économiserait que ~30-38 % d'inférences).

---

## 3. Verdict du LLM sur les 62 cas ambigus (25 pcap)

| Verdict LLM | Nombre |
|---|---|
| « MENACE » (`interesting = true`) | **50** |
| « banal » (`interesting = false`) | 12 |

À première vue : *50 menaces qu'aucune règle n'aurait vues*. **Mais c'est trompeur.**

---

## 4. ⚠️ Le problème : faux positifs massifs

La lecture des **justifications produites par le LLM lui-même** contredit son propre verdict dans la majorité des cas :

| MAC | Catégorie LLM | Justification LLM (verbatim) | Réalité |
|---|---|---|---|
| `fa:73:52:45:6d:af` | `anomaly` | *« MAC randomisé… probes wildcard pour protection de la vie privée. **Pas d'activité suspecte.** »* | ❌ faux positif |
| `2e:ee:59:c6:25:8b` | `anomaly` | *« …comportement typique d'appareils mobiles en mode protection vie privée. »* | ❌ faux positif |
| `a2:8e:ef:77:10:3f` | `anomaly` | *« …historique limité et sans signes de menace. »* | ❌ faux positif |
| `94:83:c4:a9:34:bb` | `anomaly` | *« Appareil sans comportement suspect ou inconnu. »* | ❌ faux positif |

Sur les **50 décisions « menace »**, **~40 portent sur des appareils que le LLM décrit explicitement comme civils**. En dédupliquant par MAC : **~7 téléphones civils distincts** génèrent l'essentiel du bruit (chacun re-signalé sur plusieurs fenêtres), contre **~2-3 appareils réellement dignes d'intérêt**.

### Chaîne du faux positif

1. Un téléphone à **MAC randomisé persistant** (présent sur ≥ 4 fenêtres) est escaladé au LLM par le **traqueur** (`aggregateur.py:181-188`), alors que la règle l'avait correctement classé « banal ».
2. `qwen2.5:3b` lui attribue la catégorie fourre-tout **`anomaly`** (faiblesse du petit modèle) tout en écrivant « pas d'activité suspecte » dans la raison.
3. La **logique de forçage** (`llm_analyzer.py`, version initiale) transformait toute catégorie suspecte en `interesting=true`, **en ignorant le `threat_level` et la raison bénigne** :

```python
if cat in CATEGORIES_SUSPECTES:          # "anomaly" en fait partie
    ...
    else:
        result["interesting"] = True     # ← force MENACE quoi qu'en dise la raison
```

---

## 5. La vraie plus-value existe, mais elle est noyée

Parmi les 50, **2-3 cas sont de vrais signaux** que le LLM a correctement levés et qu'**aucune règle écrite d'avance n'aurait attrapés** :

- ✅ `04:7b:cb:b9:ec:6a` — *« MAC **PERMANENT** cherchant un réseau précis (SSID 5344), **16 probes en 30 s**, potentiellement hostile ou opérationnel. »*
- ✅ `ea:4e:b3:d3:d1:0b` — *« observe plusieurs réseaux précis avec un historique constant, potentiellement reconnaissance. »*
- �◐ `80:20:da:c6:b8:20` — *« MAC permanent effectuant des probes wildcard, potentiellement surveillé. »* (limite)

C'est exactement le type de corrélation faible-signal qu'une table de seuils ne sait pas exprimer. **La capacité du LLM est réelle** — elle est simplement enterrée sous le bruit par la logique de forçage.

---

## 6. Conclusion v1

| Question | Réponse terrain |
|---|---|
| Le LLM trie-t-il mieux que les règles ? | **Non, pas en l'état** : ~80 % de ses « menaces » sont des faux positifs. |
| Apporte-t-il une capacité que les règles n'ont pas ? | **Oui** : il lève 2-3 vrais signaux comportementaux (MAC permanent en sondage agressif/reconnaissance) invisibles en tout-script. |
| Le problème est-il le modèle ou le code ? | **Les deux** : qwen sur-attribue `anomaly`, ET le forçage `catégorie → interesting` amplifie l'erreur au lieu de respecter le `threat_level`. |

**La plus-value du LLM est donc conditionnée à la correction du forçage.** Sans ça, le capteur LLM produit plus de bruit qu'un capteur tout-script (qui aurait simplement ignoré ces téléphones).

➡️ **Correctif appliqué et re-mesuré dans le rapport v2.**

---

*Mesure réalisée en SSH (`user@192.168.101.241`) via `mesure_plus_value.py`, code de prod importé sans modification. Capture arrêtée pendant la mesure pour dédier Ollama.*
