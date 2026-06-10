# À faire — backlog du capteur WiFi-LLM

> Liste des évolutions à ajouter au capteur **par la suite**. Chaque entrée :
> priorité, *pourquoi* (souvent un constat de benchmark/terrain), *comment*
> (approche/signature), effort estimé, statut. Cocher / passer en « fait » au fur
> et à mesure, et renvoyer vers le commit qui l'implémente.
>
> Légende priorité : ⭐⭐ critique (fiabilité mission) · ⭐ élevée · ○ confort.
> Dernière mise à jour : 2026-06-10.

---

## 1. Robustesse opérationnelle (prioritaire — fait *tenir* le capteur sur la durée)

### ⭐⭐ R1 — Watchdog + auto-restart  ·  statut : à faire
- **Pourquoi.** Si `capture.sh` ou `pipeline.py` meurt, **rien ne le relance**
  (un ancien crash-loop est déjà documenté en mémoire projet). Inacceptable pour un
  capteur déposé en zone sans opérateur.
- **Comment.** Service **systemd** (`Restart=always`, `WatchdogSec`) pour la capture
  et la pipeline, OU un cron-watchdog (`* * * * *`) qui `pgrep` les deux et relance
  `capteur.sh start` si absent. Logguer chaque redémarrage. Vérifier qu'on ne crée
  pas de double-démarrage (cf. mémoire `project_capteur_double_demarrage`).
- **Effort.** Faible.

### ⭐⭐ R2 — Rétention / rotation de `/data/capture/done/`  ·  statut : à faire
- **Pourquoi.** `capteur.sh status` montre **~4400 pcaps** accumulés dans `done/`. À
  quelques Mo pièce → plusieurs Go : à terme le disque sature et la **capture
  s'arrête** (mission perdue silencieusement).
- **Comment.** Purge par âge **et/ou** quota : garder N jours ou plafonner à X Go
  (supprimer les plus anciens). À brancher dans la boucle `pipeline.py` (après
  archivage) ou dans un cron horaire. Même logique applicable à `interesting/` si
  besoin. Exposer le seuil en variable d'env.
- **Effort.** Faible.

### ⭐ R3 — Plafond d'inférences LLM par fenêtre  ·  statut : à faire
- **Pourquoi.** Le benchmark a mesuré qu'une fenêtre à **3 cas ambigus ≈ 65 s**, soit
  **> la rotation de capture (30 s)** : sous trafic dense, la pipeline accumule du
  retard et prend du retard sur le temps réel.
- **Comment.** Borne `MAX_LLM_PAR_FENETRE` ; quand dépassée, prioriser les agrégats
  les plus suspects (score de règle / nb de trames d'attaque) et différer/abandonner
  le reste avec une trace. Option : file d'attente inter-fenêtres.
- **Effort.** Moyen.

### ⭐ R4 — Alerte temps réel sur menace `high`  ·  statut : à faire
- **Pourquoi.** Le push `trames/` est **post-analyse** ; aucune alerte *en direct*
  quand un événement grave survient. Un capteur tactique doit pouvoir prévenir tout
  de suite.
- **Comment.** Sur `threat_level=high` (et catégories graves), émettre une alerte :
  webhook/HTTP, notification (Tailscale/ntfy), ou au minimum une ligne de log dédiée
  `/var/log/capteur_alertes.log` + un fichier `interesting/ALERTE_*.json`. Ne jamais
  bloquer la pipeline si le canal d'alerte échoue (même philosophie que `envoi_trames`).
- **Effort.** Faible à moyen.

### ○ R5 — Horodatage + position (GPS optionnel) dans le JSON  ·  statut : à faire
- **Pourquoi.** Cartographier *où / quand* une menace apparaît — précieux en usage
  tactique, et valorise un rapport de stage.
- **Comment.** Ajouter `timestamp` (déjà dispo) + `position` (GPS USB via `gpsd` si
  présent, sinon champ vide) dans le JSON d'`extractor.py`. Dégradé proprement sans GPS.
- **Effort.** Faible (sans GPS) / moyen (avec gpsd).

### ○ R6 — Observabilité / synthèse périodique  ·  statut : à faire
- **Pourquoi.** Au-delà des logs bruts, un résumé exploitable (compteurs par
  catégorie, top menaces, MAC récurrentes) facilite l'exploitation.
- **Comment.** Script de synthèse quotidienne (cron) agrégeant les `*_analyse.json` →
  un `rapport_journalier_AAAA-MM-JJ.md`. Optionnel : métriques pour un petit dashboard.
- **Effort.** Moyen.

---

## 2. Nouvelles détections (élargir la couverture d'ennemis)

### ⭐ D1 — PMKID / attaque WPA sans client  ·  statut : à faire
- **Pourquoi.** On détecte le handshake 4-way (≥2 EAPOL) mais **pas** l'attaque
  **PMKID** (capture *clientless*, type `hcxdumptool`) : un seul EAPOL M1 portant un
  PMKID suffit à l'attaquant — signature distincte et déterministe.
- **Comment.** Extraire le champ PMKID du RSN dans le 1er message EAPOL (tshark, ex.
  `wlan.rsn.ie.pmkid` / `eapol.keydes.data`) ; règle dans `aggregateur` → catégorie
  `handshake` (ou nouvelle `pmkid`), hostile. **Vérifier le nom exact du champ sur le
  tshark du UP²** avant de coder (cf. l'incident `wlan.rsn.akms` en décimal).
- **Effort.** Faible à moyen.

### ⭐ D2 — Détection de *flood* (mdk3/mdk4) et Karma/MANA  ·  statut : à faire
- **Pourquoi.** Attaques classiques non couvertes :
  - **Beacon/SSID flood** : un même BSSID annonçant des dizaines de SSID (DoS/leurre).
  - **Karma/MANA** : un AP qui *répond* (probe response) à n'importe quel SSID sondé.
- **Comment.**
  - Flood : index inverse **BSSID→{SSID}** dans `registre_ap` ; seuil de SSID
    distincts par BSSID → catégorie `anomaly`/`flood`, déterministe.
  - Karma : capturer le subtype **`0x0005`** (probe response, *pas* filtré
    aujourd'hui dans `prefilter.INTERESTING_SUBTYPES`) ; un BSSID répondant à de
    nombreux SSID variés = Karma.
- **Effort.** Moyen.

### ○ D3 — WPS activé / verrouillage  ·  statut : à faire
- **Pourquoi.** Un AP avec WPS ouvert est une cible (attaque PIN) ou un leurre.
- **Comment.** Lire l'IE WPS du beacon (tshark `wps.*`) ; remonter en indice de
  profil (intègre le scoring beacon existant de `prefilter`).
- **Effort.** Faible.

### ○ D4 — Fingerprinting des MAC randomisées  ·  statut : idée
- **Pourquoi.** Suivre un appareil malgré la randomisation MAC (corréler les probes
  par leurs IE/ordre de tags) — avancé, fort potentiel de filature.
- **Comment.** Empreinte des Information Elements des probe requests + signal ;
  corrélation inter-fenêtres dans le `traqueur`. **Complexe, faux positifs à border.**
- **Effort.** Élevé.

---

## Cas-limites connus (suivi, pas forcément à « corriger »)

- **`f1_filature_4` / `b3`** (zone grise civile) transitent par le LLM → verdict
  **non-déterministe** d'un run à l'autre (`qwen2.5:3b`). Ce sont des *bénins* ; la
  détection des ennemis, elle, est déterministe (sauf e5/e6/e7 par conception).
  Piste si gênant : durcir le prompt « MAC randomisée = vie privée », ou ne pas
  escalader une filature randomisée tant qu'elle ne sonde qu'un seul SSID.
- **Mesh grand public** : le choix « toute infra multi-AP en zone = suspecte » peut
  générer un faux positif si un vrai mesh civil est présent — compromis assumé.

---

## Fait récemment (pour mémoire)

- ✅ Détection **mesh** (catégorie déterministe `mesh`) — commit a9137cb.
- ✅ Suppression des **modes** calibration/terrain (posture terrain unique) — a9137cb.
- ✅ **Cold-start LLM** maîtrisé (préchauffage `capteur.sh start` + keep_alive) — 7bed4a5.
- ✅ **ESP qui sonde** détecté par règle — 7464c45.
- ✅ Seuil **surveillance 5→4 SSID** (p2 déterministe) — c16bbac.
- ✅ **Benchmark** complet reproductible (`docs/benchmark_capteur.md`, `benchmark/`,
  rapports v1→v4 : rappel hostiles **14/14**, 0 faux positif).
