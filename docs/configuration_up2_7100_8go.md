# Guide de Configuration : AAEON UP² 7100 (8Go RAM)

Ce document détaille la stratégie optimale pour transformer un UP² 7100 équipé de 8 Go de RAM en une station hybride combinant analyse réseau tactique et inférence de modèles de langage (LLM) en local.

---

## 1. Choix du Système d'Exploitation (OS)

L'architecture x86_64 de l'UP² 7100 offre une grande liberté. Pour garantir la stabilité des agents IA fonctionnant en continu tout en conservant une flexibilité maximale pour les outils réseau, l'approche headless est recommandée.

*   **OS Recommandé : Debian 12 (Bookworm) - Édition Serveur**
    *   **Pourquoi :** Ultra-léger sur la RAM (environ 300-400 Mo au repos), ce qui est critique pour préserver la mémoire pour les LLM sur une machine de 8 Go. La gestion des paquets `apt` est robuste et l'environnement est parfait pour une administration à distance via SSH.
    *   **Alternative : Ubuntu Server 24.04 LTS**
        *   Plus de paquets pré-compilés pour les drivers récents et l'accélération matérielle Intel (OpenVINO), mais légèrement plus gourmand en ressources de base.

> **Astuce de configuration :** Désactiver l'interface graphique (GUI) si elle est installée. Chaque mégaoctet de RAM économisé sur l'affichage est un mégaoctet gagné pour la fenêtre de contexte du LLM.

---

## 2. Capture Wi-Fi et Mode Monitor

L'analyse de trames Wi-Fi nécessite un contrôle bas niveau sur l'interface réseau.

### Le matériel
Bien que l'UP² puisse accueillir des cartes M.2, l'approche la plus fiable pour le pentest et la capture passive reste l'utilisation d'une **carte Wi-Fi USB externe** (ex: chipset Atheros AR9271 ou MediaTek MT7612U). 
*   Les pilotes de ces puces sont intégrés nativement dans le noyau Linux standard (mac80211).
*   Elles supportent parfaitement le mode monitor et l'injection, indépendamment de la connectivité réseau principale de la carte UP².

### Les Outils à déployer
Plutôt que d'installer une distribution lourde pré-packagée, il est plus performant d'ajouter les briques nécessaires sur la base Debian :
1.  **Aircrack-ng / iw :** Pour basculer l'interface physique en mode écoute (`airmon-ng start wlan1`).
2.  **Tshark / Tcpdump :** Idéal pour automatiser la capture de trames ou de handshakes en ligne de commande, et pour parser les résultats directement vers des scripts Python ou des flux n8n.
3.  **Kismet :** Pour une cartographie passive et une journalisation avancée des appareils environnants.

---

## 3. Stratégie LLM (Contrainte des 8 Go de RAM)

Avec 8 Go de RAM partagée sur une architecture x86 (Intel Alder Lake-N), la règle d'or est de **ne pas dépasser des modèles de 7B à 8B paramètres fortement quantifiés**, afin de laisser au moins 2 Go pour Debian et les processus de capture réseau.

### Modèles Recommandés (Format GGUF / Q4_K_M)

1.  **Qwen 2.5 (3B ou 7B)** *[Le choix polyvalent]*
    *   **3B :** Consomme ~2.5 Go de RAM. Extrêmement réactif. Parfait pour être interrogé en boucle par des agents autonomes pour du parsing de logs ou de la prise de décision rapide.
    *   **7B :** Consomme ~4.5 Go de RAM. Excellent pour l'analyse de code, la compréhension de scripts d'exploitation et la logique de résolution de défis. C'est la limite haute confortable pour 8 Go.

2.  **Llama 3.2 (3B)** *[Le choix de la stabilité]*
    *   Très performant pour le respect des structures (JSON) et les instructions strictes. Idéal comme "cerveau" d'orchestration.

3.  **DeepSeek R1 Distill (Qwen 7B)** *[Le choix de la réflexion]*
    *   Variante optimisée pour les chaînes de raisonnement logique. Très pertinent pour l'analyse d'architectures réseau ou l'élaboration de méthodologies d'attaque, bien que légèrement plus lent à cause des tokens de "réflexion".

### Moteur d'inférence
*   **Ollama :** À installer en tant que service système.
*   **Accélération Intel :** L'UP² 7100 possède un iGPU Intel. Il est crucial de s'assurer que le moteur d'inférence tire parti de l'API **OpenVINO** ou de **Vulkan** pour décharger le processeur principal et fluidifier la génération des tokens.
