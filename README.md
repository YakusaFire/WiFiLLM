# Capteur WiFi embarqué avec analyse LLM

Système de capture et d'analyse automatique du trafic WiFi 802.11 en mode passif, déployé sur un Intel UP² 7100. Chaque trame capturée passe par un filtre déterministe, une agrégation comportementale par appareil, puis (pour les cas ambigus) par un LLM local (Ollama / Qwen2.5 3B) qui décide si elle mérite d'être archivée.

---

## Matériel

| Composant | Détail |
|---|---|
| Calculateur | Intel UP² 7100 — 8 Go RAM, eMMC 64 Go |
| Clé WiFi | Realtek RTL8188ETV (USB, `0bda:0179`) |
| Driver | `8188eu` (out-of-tree aircrack-ng, DKMS) |
| Réseau admin | Tailscale (IP `100.126.251.3`, nom `wifi-llm`) |
| LLM local | Ollama — modèle `qwen2.5:3b` sur `localhost:11434` |

---

## Architecture générale

```
Antenne WiFi (mode monitor)
        │
        ▼
  [capture.sh]  ──── tcpdump ───→  /data/capture/raw/raw_YYYYMMDD_HHMMSS.pcap
        │                                (rotation toutes les 30 s)
        │ channel hopping 2.4 GHz + 5 GHz (0.3 s/canal)
        │
        ▼
  [pipeline.py]  surveille /data/capture/raw/ (boucle toutes les 5 s)
        │
        ├─── [prefilter.py]  ──── tshark ──→ filtre les trames intéressantes
        │         │                           sans appel LLM
        │         │  candidats (description texte)
        │         ▼
        ├─── [aggregateur.py]  ──→ regroupe par MAC source
        │         │                  classification automatique sans LLM
        │         │                  (deauth, EAPOL, probe MAC permanent…)
        │         │  cas ambigus seulement
        │         ▼
        ├─── [llm_analyzer.py] ──→ Ollama qwen2.5:3b
        │         │                  analyse + classification
        │         │  trames jugées intéressantes
        │         ▼
        └─── [extractor.py] ──── tshark ──→ /data/capture/interesting/
                                              *.pcap  +  *_analyse.json
        │
        ▼
  pcap traité déplacé vers /data/capture/done/

  [traqueur.py]  (objet partagé dans pipeline.py)
        └── historique inter-pcap des appareils observés
              → escalade au LLM si appareil persistant ou en reconnaissance

  [registre_ap.py]  (objet partagé, PERSISTANT sur disque)
        └── carte SSID→BSSID sur des jours/semaines
              → un nouveau BSSID sur un SSID déjà connu (evil twin) est
                escaladé au LLM avec une comparaison des AP (antériorité,
                signal, sécurité, vendor, canal)
```

---

## Fichiers du projet

| Fichier | Rôle |
|---|---|
| `scripts/capteur.sh` | Script de contrôle : start / stop / restart / status / logs |
| `scripts/capture.sh` | Capture brute 802.11 — mode monitor + channel hopping + tcpdump |
| `pipeline.py` | Orchestrateur : surveille les pcap et enchaîne les étapes |
| `prefilter.py` | Filtre déterministe — extrait et décrit les trames suspectes |
| `aggregateur.py` | Agrégation par MAC + classification automatique sans LLM |
| `traqueur.py` | Traqueur inter-pcap — historique de persistance des appareils (RAM) |
| `registre_ap.py` | Registre **persistant** des AP (carte SSID→BSSID) — détection d'evil twin |
| `oui.py` | Résolution OUI → fabricant (base `manuf` de Wireshark) + mode calibration/terrain |
| `llm_analyzer.py` | Interface Ollama — prompt + parsing de la réponse JSON |
| `extractor.py` | Extraction des trames retenues dans un pcap + JSON d'analyse |
| `scripts/send_data.sh` | Exfiltration des pcap suspects vers un serveur distant via modem 4G |
| `mesure_plus_value.py` | Outil de mesure : quantifie le split règle/LLM et la plus-value du LLM sur pcap réels ou corpus démo |
| `tests/` | Tests fonctionnels et de sécurité (`test_batterie`, `test_complet`, `test_prefilter`, `test_registre_ap`, `test_securite`) — lançables en direct (`python3 tests/test_xxx.py`) ou via pytest depuis la racine |
| `docs/` | Documentation : guide capteur, configuration UP², notes (Idee, realiser, plusvalue, avantage/inconvénient) + datasheet |
| `rapport/` | Rapports de tests et de mesure de plus-value (v1 = constat faux positifs, v2 = après correctif) |

---

## Détail de chaque composant

### `capteur.sh` — Contrôle du système

Script principal à utiliser sur le UP² pour démarrer ou arrêter l'ensemble.

```bash
bash /root/capteur.sh start    # Lance capture + pipeline
bash /root/capteur.sh stop     # Arrête tout proprement
bash /root/capteur.sh restart  # Redémarre
bash /root/capteur.sh status   # État des processus + stats fichiers
bash /root/capteur.sh logs     # 20 dernières lignes du log pipeline
```

Au démarrage (`start`), le script :
1. Passe l'interface `wlx64d95401ebeb` en **mode monitor** via `iw dev`
2. Crée les dossiers `/data/capture/{raw,done,interesting}` si absents
3. Purge les `.pyc` pour forcer le rechargement du code Python
4. Lance `capture.sh` et `pipeline.py` en arrière-plan avec `nohup`

---

### `capture.sh` — Capture brute 802.11

Deux processus parallèles :

**Channel hopping** (arrière-plan) : bascule l'interface sur chaque canal 2.4 GHz (1–11) puis 5 GHz (36–140 DFS inclus) toutes les 300 ms. Cela couvre l'ensemble du spectre sans rester bloqué sur un seul canal.

**tcpdump** (boucle principale) : capture toutes les trames 802.11 de type management (`type mgt`) et data (`type data`) pendant 30 secondes, puis crée un nouveau fichier horodaté. La rotation toutes les 30 s garantit que les fichiers restent petits et que la pipeline les traite rapidement.

```
/data/capture/raw/raw_20260603_123456.pcap   ← fichier en cours
/data/capture/raw/raw_20260603_123526.pcap   ← suivant (30 s plus tard)
```

Format de capture : `IEEE802_11_RADIO` (radiotap header + 802.11) — compatible Wireshark.

---

### `pipeline.py` — Orchestrateur

Boucle infinie avec un délai de 5 secondes. Un `Traqueur` est instancié au démarrage et partagé sur toute la durée de vie du processus pour la mémoire inter-pcap.

À chaque itération, il cherche les fichiers `.pcap` non encore traités dans `/data/capture/raw/`, les traite dans l'ordre chronologique, puis déplace chaque fichier dans `/data/capture/done/` une fois terminé.

Pour chaque fichier :
```
filtrer_pcap(pcap) → liste de candidats
    si vide → "Aucun candidat", déplace le fichier
    sinon → agreger(candidats, traqueur) → liste d'agrégats par MAC

    pour chaque agrégat :
        si classification automatique disponible :
            → log + ajout direct si interesting=true
        sinon (cas ambigu) :
            → analyser(description) → LLM
            → ajout si interesting=true

    si intéressants > 0 → extraire(pcap, intéressants) → pcap + json dans interesting/
```

Logs dans `/var/log/capteur.log`.

---

### `prefilter.py` — Filtre déterministe

Lit le pcap avec `tshark -T json -e field...` et inspecte chaque trame **sans appel réseau**. Son rôle est d'éliminer la majorité du trafic banal (beacons WPA2 standard, trames data chiffrées banales) avant l'agrégation et l'éventuel appel LLM.

**Trames systématiquement retenues :**

| Type | Code | Raison |
|---|---|---|
| Probe Request | `0x0004` | Révèle les réseaux connus d'un appareil |
| Association Request/Response | `0x0000`, `0x0001` | Tentative de connexion à un AP |
| Authentication | `0x000b` | Échange d'authentification 802.11 |
| Deauthentication | `0x000c` | Déconnexion forcée — possible attaque |
| Disassociation | `0x000a` | Déconnexion |
| EAPOL | — | Handshake WPA2 4-way |

**Beacons (`0x0008`) : tous inventoriés, dédupliqués par BSSID.** Depuis l'ajout de la détection d'evil twin, *tous* les beacons sont remontés (un seul par BSSID, celui au signal le plus fort) pour alimenter le registre persistant `SSID→BSSID`. Le canal (`wlan.ds.current_channel`, sinon `wlan_radio.channel`) est extrait comme discriminant. Un beacon banal est enregistré au registre puis classé bénin par `aggregateur.py` (il n'atteint pas le LLM) ; le **score de sécurité ≥ 3** ne décide plus de la *capture* mais sert à escalader un beacon **sur-sécurisé** (`over_secured`) au LLM. Ce score cumule :

| Indice | Points |
|---|---|
| SSID masqué | +2 |
| WPA3-SAE | +3 |
| WPA2-Enterprise / EAP | +2 |
| GCMP-256 | +2 |
| GCMP-128 | +1 |
| PMF obligatoire (802.11w) | +3 |
| PMF activé | +1 |
| Signal > −25 dBm (antenne directionnelle probable) | +2 |
| Beacon interval non standard (< 50 ou > 200 TU) | +1 |

Un réseau domestique WPA2-PSK standard ne dépasse jamais 1–2 points. Un réseau combinant WPA3 + PMF obligatoire + SSID masqué atteint 8 points — profil atypique pour un civil.

**Descriptions enrichies pour le LLM :**

- SSID : décodé depuis l'hexadécimal tshark en UTF-8 lisible
- MAC : détection automatique si randomisé (bit locally-administered = 1 dans le premier octet)
- Probe Request ciblé : `"cherchant le réseau connu 'FreeWifi' (probe ciblé — révèle l'historique réseau)"`
- Probe Request wildcard : `"cherchant n'importe quel réseau (wildcard probe)"`

---

### `aggregateur.py` — Agrégation comportementale par MAC

Regroupe tous les candidats d'un pcap par **adresse MAC source**, construit une description comportementale synthétique, puis tente une **classification automatique sans appel LLM** pour les cas évidents.

**Cas classifiés automatiquement :**

| Condition | Catégorie | Niveau |
|---|---|---|
| Wildcard probes ou probes ciblés depuis MAC randomisé, sans deauth ni EAPOL | `normal` | none — ignoré |
| Deauth broadcast (`ff:ff:ff:ff:ff:ff`) | `deauth_attack` | medium / high (≥ 5 deauth) |
| ≥ 3 deauthentifications ciblées | `deauth_attack` | medium |
| ≥ 2 trames EAPOL | `handshake` | medium |
| MAC permanent sondant ≥ 5 SSID distincts | `surveillance` | medium |

Les cas non couverts par ces règles sont transmis au LLM avec la description comportementale complète (nombre de trames, types, SSIDs sondés, signal min/max, historique traqueur).

**Interaction avec le traqueur :**

Si un appareil à MAC randomisé serait normalement ignoré mais que le `Traqueur` le juge persistant ou en reconnaissance active, son cas est **escaladé au LLM** avec le contexte historique ajouté à la description.

**Interaction avec le registre AP (evil twin) :**

Pour chaque beacon, le BSSID (= MAC source de l'AP) et son SSID sont enregistrés dans `registre_ap.py`. Si le registre retourne le statut `conflit` (nouveau BSSID sur un SSID déjà connu), le cas est **escaladé au LLM** avec la **comparaison des AP** ajoutée à la description — cela prime sur l'apaisement `infra_connue`, comme une attaque dure. Un beacon ordinaire sans conflit ni sur-sécurisation est classé **bénin** de façon déterministe (il alimente le registre mais n'atteint pas le LLM).

---

### `traqueur.py` — Mémoire inter-pcap

Maintient l'historique de chaque appareil observé **entre les pcap successifs**, permettant de distinguer un passant (vu 1 fois) d'un appareil qui stationne ou fait de la reconnaissance.

**Niveaux d'évaluation :**

| Niveau | Condition | Action |
|---|---|---|
| `ignorer` | Première apparition ou comportement banal | Pas d'escalade |
| `surveiller` | Vu ≥ 2 fois | Pas d'escalade mais suivi actif |
| `llm` | Vu ≥ 4 fois (persistance) **ou** ≥ 5 SSID distincts (reconnaissance) | Escalade au LLM |

**Paramètres :**

| Paramètre | Valeur | Rôle |
|---|---|---|
| `SEUIL_PERSISTANCE` | 4 apparitions | Seuil d'escalade pour un appareil stationnaire |
| `SEUIL_SSID_DIVERSITE` | 5 SSID distincts | Seuil de détection de cartographie WiFi active |
| `FENETRE_OUBLI` | 600 s (10 min) | Durée sans activité avant suppression de l'historique |

Le contexte historique ajouté à la description LLM précise le nombre d'apparitions, la durée de présence, et les SSIDs cumulés.

---

### `registre_ap.py` — Registre persistant des AP (détection d'evil twin)

Pendant **persistant sur disque** du traqueur, dédié aux points d'accès. Là où le traqueur oublie en RAM après 10 min, le registre maintient sur **des jours/semaines** la carte `SSID → {BSSID → caractéristiques}` (vendor OUI, canal, profil de sécurité, signal max, antériorité). C'est cette mémoire longue qui rend la détection d'**evil twin** possible : savoir qu'un BSSID est légitime *parce qu'il émet ce SSID depuis longtemps*.

**Principe — l'antériorité fait la légitimité.** Le BSSID vu en premier / le plus souvent pour un SSID est la **référence présumée** ; un BSSID qui apparaît **ensuite** sur ce SSID établi est un *nouveau venu* suspect. Le registre ne **juge pas** : il détecte le **conflit** et fournit une **comparaison** des AP en présence. C'est le LLM, en aval, qui désigne l'imposteur (critère : signal plus fort, sécurité plus faible, vendor ou canal différents).

| Méthode | Rôle |
|---|---|
| `nouvelle_fenetre()` | Marque le passage à un nouveau pcap (1 apparition comptée par fenêtre) |
| `observer(ssid, bssid, infos)` | Enregistre/actualise un AP → statut `premier_du_ssid` / `connu` / `conflit` |
| `description_comparative(ssid)` | Texte comparatif (antériorité, vendor, sécurité, canal, signal) injecté dans le prompt LLM |
| `purger(max_age_jours)` | Oublie les BSSID inactifs depuis > 14 jours |
| `charger()` / `sauver()` | Persistance JSON atomique (`/data/capture/registre_ap.json`) |

**Statut `conflit`** = ce SSID a ≥ 2 BSSID distincts **et** le BSSID courant est un *nouveau venu* (vu sur ≤ 2 fenêtres). Ce critère couvre le cas réaliste (référence ancienne + pirate récent) comme le démarrage à froid (deux AP découverts dans la même fenêtre, le LLM tranchant alors sur signal/sécurité/vendor). Un réseau **mesh/multi-AP légitime**, une fois ses BSSID stabilisés, repasse en `connu` et ne ré-escalade plus (anti-bruit). Les **SSID masqués** ne sont pas indexés (un evil twin imite un SSID *visible* ; le masqué reste géré par `over_secured`).

---

### `oui.py` — Résolution fabricant (OUI)

Donne le **fabricant** d'une MAC à partir de son **OUI** (les 3 premiers octets, attribués par l'IEEE), par lookup déterministe contre la base `manuf` de Wireshark — **jamais** via le LLM (qui hallucinerait les marques). `aggregateur.py` injecte ce fabricant dans la description envoyée au LLM.

- Ne résout que les **MAC permanentes** : une MAC randomisée (bit `0x02`) a un OUI bidon → retourne `None`.
- **Mode d'emploi** (variable d'env `CAPTEUR_MODE`, défaut `calibration`) :

| Mode | Matériel maison (`FABRICANTS_SITE` : GL.iNet, Sagemcom…) |
|---|---|
| `calibration` | Atelier/bureau → **bénin** : `[équipement habituel du site]` (évite les faux positifs sur sa propre flotte) |
| `terrain` | Capteur déposé en zone, passif → **suspect** : `[matériel … suspect en zone opérationnelle]` (matériel adverse probable) |

> Dans les deux modes, un `deauth`/`handshake` émis par ces équipements reste détecté par les règles déterministes — le mode ne joue que sur le jugement « mou » du LLM. Pour déployer en zone : `CAPTEUR_MODE=terrain`.

---

### `llm_analyzer.py` — Analyse par LLM

Envoie la description comportementale agrégée d'un appareil à Ollama (`qwen2.5:3b` sur `localhost:11434`) et parse la réponse JSON. N'est appelé que pour les cas **non résolus par la classification automatique** de `aggregateur.py`.

**Catégories de sortie :**

| Catégorie | Description |
|---|---|
| `normal` | Trame banale, pas d'intérêt |
| `probe_tracking` | Appareil cherche un réseau connu — traçage possible |
| `deauth_attack` | Déauthentification suspecte — possible attaque de déconnexion |
| `handshake` | Capture d'un handshake WPA2 4-way |
| `over_secured` | Réseau avec profil de sécurité anormal pour un civil |
| `evil_twin` | AP imitant un réseau légitime (même SSID, BSSID différent) — alimenté par `registre_ap.py` (jugement par antériorité) |
| `covert_ap` | Point d'accès clandestin |
| `surveillance` | Balayage actif de probes ou comportement de surveillance |
| `anomaly` | Comportement 802.11 anormal non classifié |

**Logique `interesting` après réponse du LLM :**

Le `threat_level` jugé par le LLM est la **source de vérité**, pas la seule catégorie.

- Catégories d'attaque **dures** (`CATEGORIES_GRAVES` = `deauth_attack`, `handshake`, `evil_twin`, `covert_ap`, `over_secured`) → `interesting=true` (filet de sécurité ; `threat_level` remonté à `medium` s'il valait `none`)
- Catégories **molles** (`probe_tracking`, `surveillance`, `anomaly`) → `interesting=true` **uniquement si** `threat_level` ∈ {`medium`, `high`} ; sinon `false`
- `normal` ou catégorie inconnue → `interesting=false`
- En cas de timeout (> 60 s) ou d'erreur → `interesting=false`

> **Pourquoi cette logique** : forcer `interesting=true` sur la seule catégorie générait un fort taux de faux positifs sur le terrain — `qwen2.5:3b` sur-attribue `anomaly` à des MAC randomisés civils tout en les décrivant comme bénins. Faire piloter `interesting` par le `threat_level` corrige ça (cf. `rapport/rapport_plus_value_v1.md` → `v2.md`).

---

### `extractor.py` — Extraction des trames retenues

Pour chaque fichier pcap contenant au moins une trame intéressante, extrait exactement les trames concernées (par numéro de frame) dans un nouveau pcap, et génère un fichier JSON d'analyse à côté. Tolère le code de retour 2 de tshark (pcap tronqué en capture live — les trames lues restent valides).

```
/data/capture/interesting/
├── raw_20260603_125601_20260603_125656.pcap        ← trames extraites
└── raw_20260603_125601_20260603_125656_analyse.json ← rapport LLM
```

Le JSON contient pour chaque trame : le numéro, la description textuelle, les métadonnées brutes (layers tshark) et la réponse complète du LLM (`interesting`, `threat_level`, `category`, `reason`).

---

### `send_data.sh` — Exfiltration via modem 4G

Script déclenché manuellement (ou par cron) pour exfiltrer les pcap suspects vers un serveur distant lorsque le réseau Tailscale n'est pas disponible.

Fonctionnement :
1. Vérifie qu'il y a des fichiers `.pcap` dans `/data/capture/interesting/`
2. Active le modem 4G via `ModemManager` (`mmcli`) sur l'APN configuré
3. Transfère les fichiers avec `rsync` (suppression source après envoi réussi)
4. Désactive le modem pour économiser la batterie

Variables à configurer en tête de script : `MODEM_APN`, `REMOTE_USER`, `REMOTE_HOST`, `REMOTE_PATH`.

---

## Logs

| Fichier | Contenu |
|---|---|
| `/var/log/capteur.log` | Log principal de la pipeline (trames trouvées, résultats LLM, fichiers extraits) |
| `/var/log/capture.log` | Log de capture.sh (démarrage, mode monitor, rotations) |

Exemple de log pipeline :

```
13:00:00 Pipeline démarré
13:00:05 → raw_20260603_130000.pcap
13:00:05   12 trame(s) → 4 appareil(s)
13:00:05   ✗ ignoré (da:4f:...) — Probes depuis MAC randomisé — protection vie privée standard
13:00:05   ⚡ [medium] handshake — Handshake WPA complet capturé (4 trames EAPOL)
13:00:38   ✓ [low] probe_tracking (c4:a5:...) — Appareil avec MAC permanent cherchant un réseau connu.
13:00:38   Extrait → raw_20260603_130000_20260603_130038.pcap
13:00:38 → raw_20260603_130030.pcap
13:00:38   3 trame(s) → 1 appareil(s)
13:01:10   ⚡ [high] deauth_attack — 7 deauthentification(s) broadcast en 30s
13:01:10   Extrait → raw_20260603_130030_20260603_130110.pcap
```

---

## Structure des dossiers sur le UP²

```
/root/
├── capteur.sh        ← script de contrôle
├── capture.sh        ← capture brute
├── pipeline.py       ← orchestrateur
├── prefilter.py      ← filtre déterministe
├── aggregateur.py    ← agrégation comportementale par MAC
├── traqueur.py       ← mémoire inter-pcap des appareils (RAM)
├── registre_ap.py    ← registre persistant SSID→BSSID (détection evil twin)
├── oui.py            ← résolution OUI → fabricant + mode calibration/terrain
├── llm_analyzer.py   ← interface LLM
├── extractor.py      ← extraction des résultats
└── send_data.sh      ← exfiltration 4G (optionnel)

/data/capture/
├── raw/              ← pcap en cours de traitement (rotation 30 s)
├── done/             ← pcap traités et archivés
├── interesting/      ← pcap + JSON des captures suspectes retenues
└── registre_ap.json  ← carte persistante SSID→BSSID (détection evil twin)

/var/log/
├── capteur.log       ← log pipeline
└── capture.log       ← log capture
```

---

## Dépendances système (UP² — Debian 12)

```bash
apt install tcpdump tshark python3 python3-requests
# Driver WiFi out-of-tree (monitor mode) :
apt install dkms build-essential linux-headers-$(uname -r)
git clone https://github.com/aircrack-ng/rtl8188eus
cd rtl8188eus && make && make install
echo "8188eu" >> /etc/modules
echo "blacklist r8188eu" > /etc/modprobe.d/blacklist-r8188eu.conf
# LLM local :
# Installer Ollama puis : ollama pull qwen2.5:3b
# Exfiltration 4G (optionnel) :
apt install modemmanager
```

---

## Accès distant

Le UP² est accessible via Tailscale :

```bash
ssh user@100.126.251.3   # puis : su -
```

Depuis la machine de développement, les scripts Python utilisent `paramiko` avec les identifiants stockés dans `.env` pour déployer les fichiers et exécuter des commandes à distance.
