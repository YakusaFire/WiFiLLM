# Plus-value du LLM dans le capteur WiFi

## Ce que les règles font (35 % du flux)

Les règles déterministes tranchent les cas évidents avec une fiabilité totale et sans coût :
- deauth broadcast → attaque de déconnexion
- ≥ 2 trames EAPOL → capture de handshake WPA2
- MAC permanent sondant ≥ 5 SSID distincts → reconnaissance
- MAC randomisé avec probes wildcard → ignoré (vie privée civile)

Ces cas ne nécessitent pas de LLM. La règle gagne toujours sur le déterministe.

## Ce que les règles ne peuvent pas faire (65 % du flux)

Un script agit sur des valeurs fixes. S'il n'y a pas 3 deauth, il ne fait rien. Face à une combinaison ambiguë — 2 probes + 1 auth + signal fort + SSID précis — il n'a qu'un choix : inventer un seuil arbitraire ou jeter le cas en silence.

Le LLM évalue la **combinaison** : fréquence de probes, MAC identifiable ou randomisé, cible précise ou wildcard, signal, historique de persistance. Il peut aussi inférer l'**intention** : un appareil qui a enchaîné probe → auth → deauth n'est pas juste "une deauth", c'est quelqu'un qui a testé une connexion puis forcé une déconnexion — comportement d'attaquant, pas de passant.

## Ce que mesure le terrain (94 décisions sur 25 pcap réels — rapport v2)

| | Règle seule | Script+LLM (v2 corrigé) |
|---|---|---|
| Faux positifs civils flaggés | 0 (règles OK) | 0 (après correctif) |
| Zone grise qualifiée | ✗ jetée en silence | ✅ 5 appareils défendables levés |
| probe_tracking MAC permanent | ✗ invisible | ✅ détecté |
| Appareil persistant sur SSID précis | ✗ invisible | ✅ détecté |

Les 5 appareils retenus après correctif : 4 MAC permanents en sondage actif + 1 MAC randomisé mais persistant sur une cible précise. Aucun téléphone "vie privée" banal.

## La plus-value en une phrase

> Le LLM ne détecte pas plus que les règles sur les cas clairs — il transforme un détecteur à seuils figés en capteur qui **qualifie l'ambigu** : comportements que nulle règle écrite d'avance n'exprime, à condition de lui faire confiance sur son `threat_level` et non sur sa seule catégorie.