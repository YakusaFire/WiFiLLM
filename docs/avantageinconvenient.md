# Avantages et inconvénients — LLM vs capteur tout-script

## Avantages du LLM

**Qualifie l'ambigu sans seuil figé**
Un script doit décider à l'avance : "si ≥ 3 deauth alors attaque". Le LLM évalue une combinaison d'indices sans règle préécrite — 2 probes + signal fort + SSID précis + MAC permanent peut suffire à lever une alerte là où le script passerait en silence.

**Comprend l'intention derrière la séquence**
Un attaquant qui enchaîne probe → auth → deauth n'est pas "juste une deauth". Le LLM voit la séquence complète et peut inférer le comportement (reconnaissance, test de connexion, déconnexion forcée) plutôt que de réagir trame par trame.

**Produit une raison lisible**
Chaque décision LLM inclut un champ `reason` en langage naturel. L'analyste comprend immédiatement pourquoi un appareil a été flaggé, sans relire le code ni interpréter un score numérique opaque.

**S'adapte aux cas que le script ne prévoit pas**
Un nouveau comportement 802.11 (protocole inhabituel, combinaison rare) n'exige pas de modifier le code. Le LLM peut le classer dans `anomaly` ou le rapprocher d'une catégorie existante sans mise à jour.

**Contextualise le fabricant et la persistance**
Le LLM reçoit le fabricant (OUI résolu) et l'historique du traqueur. Il peut pondérer différemment un équipement Cisco qui sonde un SSID précis depuis 20 minutes et un téléphone Samsung vu une fois.

---

## Inconvénients du LLM

**Lent**
Sur qwen2.5:3b en local, une analyse prend 5 à 45 secondes. Un script répond en millisecondes. Pour un capteur temps réel sur trafic dense, c'est un goulot d'étranglement — d'où le préfiltre déterministe qui limite les appels LLM aux seuls cas ambigus.

**Faux positifs si mal cadré**
Sans contrainte sur le `threat_level`, qwen2.5:3b sur-attribue la catégorie `anomaly` à des téléphones civils qu'il décrit lui-même comme bénins. La v1 du pipeline forçait `interesting=true` sur la catégorie seule → 6 faux positifs sur 25 pcap. Corrigé en v2 en pilotant sur le `threat_level`.

**Réponse non déterministe**
Deux appels identiques peuvent donner des réponses différentes. Un script à règles est 100 % reproductible. Le LLM ne l'est pas — ce qui complique le débogage et les tests de non-régression.

**Dépendant du prompt et du modèle**
La qualité de la sortie dépend entièrement de la formulation du prompt et du modèle utilisé. Un changement de modèle (qwen2.5:3b → autre) peut tout casser sans avertissement. Les règles déterministes, elles, ne dépendent de rien d'externe.

**Ne remplace pas les règles sur les cas clairs**
Sur les attaques caractérisées (deauth broadcast, handshake EAPOL), le script est plus fiable que le LLM — il ne peut pas halluciner ni rater une règle précise. Vouloir supprimer les règles au profit du seul LLM serait une régression.

**Consomme des ressources**
Ollama + qwen2.5:3b tourne en permanence en RAM sur le UP². Sur un matériel contraint, c'est une charge non négligeable pour un modèle qui n'est appelé que sur les cas ambigus.

---

## Synthèse

| Critère | Tout-script | Script + LLM |
|---|---|---|
| Vitesse de décision | ✅ immédiate | ⚠ 5–45 s sur cas ambigus |
| Fiabilité sur cas clairs | ✅ totale | ✅ totale (règles conservées) |
| Qualification de la zone grise | ✗ aveugle | ✅ exploitable |
| Faux positifs | ✅ nuls (si règles bien écrites) | ⚠ nécessite calibration du prompt |
| Explicabilité | ⚠ score numérique | ✅ raison en langage naturel |
| Reproductibilité | ✅ déterministe | ⚠ non déterministe |
| Adaptabilité à l'inconnu | ✗ rigide | ✅ classifie sans mise à jour code |
| Charge système | ✅ négligeable | ⚠ Ollama permanent en RAM |

**Conclusion** : le LLM ne remplace pas les règles, il les complète. La bonne architecture est un préfiltre déterministe qui élimine l'évident, et un LLM qui qualifie ce que les règles ne peuvent pas exprimer — à condition de lui faire confiance sur son niveau de menace plutôt que de forcer sur la catégorie.
