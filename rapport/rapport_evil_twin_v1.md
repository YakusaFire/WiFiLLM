# Rapport — Détection des *evil twins* (v1)

**Date :** 2026-06-05
**Périmètre :** implémentation + validation **locale** de la logique (le verdict LLM final se valide sur le UP²).
**Décisions cadrées avec l'opérateur :** (a) *le LLM tranche* — le registre détecte le conflit et fournit la comparaison, `qwen2.5:3b` désigne l'imposteur ; (b) *local d'abord* — déploiement UP² différé.

> Comble le trou fonctionnel documenté dans le [rapport plus-value v2](rapport_plus_value_v2.md) §5 et le test `E1` de `test_batterie.py` (jusqu'ici marqué *« GAP — RATÉ, gap documenté »*).

---

## 1. Pourquoi l'evil twin n'était pas détecté

Trois causes structurelles, toutes levées par cette v1 :

| Cause | Avant | Après |
|---|---|---|
| Agrégation **par MAC source** → chaque AP jugé isolément | `aggregateur.py` ne comparait jamais 2 BSSID d'un même SSID | Le registre compare les BSSID d'un même SSID |
| Mémoire **RAM, oubli 10 min** (`traqueur.py`) | Impossible d'établir l'antériorité d'un BSSID | `registre_ap.py` **persiste** la carte SSID→BSSID (horizon 14 j) |
| `prefilter.py` ne remontait **que les beacons sur-sécurisés** | L'evil twin d'une box civile banale n'entrait pas dans le pipeline | **Tous** les beacons sont inventoriés (dédupliqués par BSSID) |

---

## 2. Méthode — l'antériorité fait la légitimité

1. **Inventaire.** `prefilter.py` remonte désormais tous les beacons (1 par BSSID, signal le plus fort) et extrait le **canal** (`wlan.ds.current_channel`, sinon `wlan_radio.channel`).
2. **Mémoire persistante.** `registre_ap.py` maintient `SSID → {BSSID → {antériorité, vendor OUI, canal, profil sécurité, signal max}}` sur disque (`/data/capture/registre_ap.json`, écriture atomique, purge > 14 j).
3. **Déclenchement (déterministe).** Statut `conflit` = un SSID a ≥ 2 BSSID **et** le BSSID courant est un *nouveau venu* (vu sur ≤ 2 fenêtres). Couvre le cas réaliste (référence ancienne + pirate récent) **et** le démarrage à froid (2 AP dans la même fenêtre).
4. **Jugement (LLM).** Le registre n'émet **aucun verdict** : il injecte une **comparaison** des AP (antériorité, signal, sécurité, vendor, canal) dans la description, et `llm_analyzer.py` (prompt enrichi) **désigne l'imposteur** — nouveau venu au signal plus fort / sécurité plus faible / vendor ou canal différents → `evil_twin`. À l'inverse, AP de même vendor + même sécurité → *mesh légitime*, `interesting=false`.

**Anti-bruit.** Un réseau mesh/multi-AP légitime, une fois ses BSSID stabilisés (> 2 fenêtres), repasse en `connu` et **ne ré-escalade plus**. Les SSID masqués ne sont pas indexés (restent gérés par `over_secured`).

---

## 3. Résultats des tests locaux

### `test_registre_ap.py` (logique cœur, sans réseau) — **21/21 assertions vertes**

| Groupe | Vérifie | Résultat |
|---|---|---|
| Antériorité + conflit | LEGIT établi 5 fenêtres, ROGUE → `conflit` ; comparaison marque ANTÉRIEUR / NOUVEAU VENU, signaux comparés | ✅ |
| Conflit même fenêtre (E1) | 2 beacons même SSID/fenêtre → `conflit` au 2ᵉ | ✅ |
| Pas de faux conflit | BSSID unique → jamais `conflit` ; mesh stabilisé → `connu` | ✅ |
| Persistance | sauver → recharger = même état, compteur de fenêtre repris | ✅ |
| Purge | BSSID inactif 30 j supprimé, frais conservé | ✅ |

### `test_batterie.py` (intégration aggregateur) — **E1 et E2 verts**

- **E1 [evil twin]** — ROGUE (`00:de:ad:be:ef:00`, signal −30) usurpe `Wifi_Cafe` (réf `80:20:da:…`, −68) : **ROGUE escaladé au LLM** (`auto=None`), **comparaison injectée**, **référence laissée bénigne**. → le *GAP* historique est comblé.
- **E2 [mesh légitime]** — 2 AP même SSID stabilisés sur 5 fenêtres : **plus aucune escalade** en régime établi (anti-bruit confirmé).

> Les scénarios `L*`/`M*` de la batterie restent « ratés » **en local** car ils dépendent d'Ollama et de la base `manuf` (absents de la machine de dev) — ce n'est pas une régression : les 7 détections par **règle déterministe** (deauth, handshake, surveillance) et le seul beacon masqué (`L2 → over_secured`) sont inchangés. Ces cas se revalident sur le UP².

---

## 4. Ce que ça change dans la chaîne

| Étape | Modification |
|---|---|
| `prefilter.py` | + champ canal ; tous les beacons remontés, dédupliqués par BSSID |
| `registre_ap.py` | **nouveau** — mémoire persistante + détection de conflit + comparaison |
| `aggregateur.py` | branche le registre ; `conflit` → escalade LLM (prime sur `infra_connue`) ; beacon banal → bénin déterministe |
| `pipeline.py` | instancie / charge / sauve / purge le registre |
| `llm_analyzer.py` | prompt evil_twin : critère d'antériorité + garde-fou mesh |

---

## 5. Limites & suite

- **Verdict LLM non encore mesuré sur le terrain.** La v1 valide le *déclenchement* et la *comparaison* (déterministes) ; la qualité du jugement `evil_twin` vs `mesh légitime` par `qwen2.5:3b` reste à mesurer sur le UP² (Ollama).
- **Beacons seulement.** Les *Probe Responses* (autre vecteur d'usurpation) ne sont pas encore exploitées.
- **Bruit résiduel possible** à l'apparition d'un BSSID légitime (répéteur ajouté) : 1 à 2 escalades avant stabilisation — acceptable, réglable via `SEUIL_ALERTE_FENETRES`.
- **Démarrage à froid** : sans antériorité, le LLM tranche sur signal/sécurité/vendor uniquement — moins robuste qu'avec un registre déjà mûri.
- **Déploiement UP² à faire** (choix « local d'abord ») : pousser `registre_ap.py` + les fichiers modifiés, vérifier `/data/capture/registre_ap.json`, provoquer un faux SSID jumeau et lire le verdict dans `/var/log/capteur.log` + `interesting/`. À coordonner avec le nettoyage du double-démarrage du capteur.

---

*Logique validée en local (machine de dev, sans tshark/Ollama). Tests : `python3 test_registre_ap.py` (21/21) et `python3 test_batterie.py` (E1/E2 verts).*
