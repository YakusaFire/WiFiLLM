# Idée projet capteur llm

## Petit modèle

### Pi avec 8Go

#### La catégorie "Lightweight" (<= 3B)

Ces modèles sont tes alliés pour la réactivité, les agents n8n qui demandent une faible latence ou des tâches d'automatisation simples.

    Llama 3.2 (3B) : Le standard indétrônable. Extrêmement rapide, très stable, et parfait pour le suivi d'instructions. C'est le choix par défaut pour tout agent qui doit répondre en moins d'une seconde.

    Qwen 2.5 (1.5B ou 3B) : Souvent plus performant que Llama 3.2 sur des tâches spécifiques de codage ou de logique multilingue. Ils sont extrêmement bien optimisés pour les architectures ARM.

    SmolLM2 (1.7B) : Si tu cherches le modèle le plus "léger possible" tout en restant capable de raisonner, celui-ci est une pépite de compacité.

### Pi avec 16Go

#### La catégorie "Mid-Range" (8B à 14B)

Avec 16 Go de RAM, c'est ici que tu gagnes en "intelligence" réelle. Ces modèles peuvent gérer des repo-code entiers, du raisonnement complexe et une meilleure analyse de contexte.

    Qwen 2.5 (7B ou 14B) :

        Le 7B est excellent pour un équilibre parfait vitesse/intelligence.

        Le 14B est le "sweet spot" pour 16 Go de RAM. Il est nettement plus capable pour le débogage complexe et les tâches d'ingénierie agentique (SWE-bench).

    Llama 3.1 (8B) : Le choix de la sécurité. Il est extrêmement fiable pour le respect du format JSON, ce qui est crucial si tes agents (n8n/Python) attendent une sortie structurée pour continuer leurs actions.

    Phi-4 (14B) : C'est actuellement le modèle de référence pour le "raisonnement" dans cette catégorie de taille. Si ton projet CTFDestructor nécessite de résoudre des problèmes mathématiques ou logiques ardus, c'est celui que tu devrais tester en priorité.

    DeepSeek R1 Distill (Qwen 14B) : Un modèle "distillé" du puissant modèle de raisonnement DeepSeek R1. Il intègre une forme de capacité de réflexion ("thinking") qui le rend particulièrement redoutable pour les CTF où il faut réfléchir à une stratégie d'attaque avant d'agir.



## OS raspberry pi


    OS : Raspberry Pi OS 64-bit. 

    Réseau : une carte Wi-Fi externe compatible mode moniteur.

    Outils :

        Capture : tshark 

        IA : Ollama tournant en service système (systemd), accessible via API locale.

## Matériel

    UP² 7100 8Go 64GB

    Carte WIFI externe

