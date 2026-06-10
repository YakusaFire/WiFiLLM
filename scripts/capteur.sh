#!/bin/bash
# =============================================================================
#  capteur.sh — Point d'entrée unique pour opérer le capteur WiFi LLM
# =============================================================================
#  Rôle       : Contrôle l'ensemble du système (capture + pipeline). Passe
#               l'interface WiFi en mode monitor, crée les dossiers de travail,
#               lance ou arrête les deux processus, et expose un état synthétique.
#
#  Usage      : bash /root/capteur.sh <commande>
#  Commandes  :
#    start    — Mode monitor + dossiers + préchauffe LLM + capture & pipeline + watchdog
#    stop     — Désarme le watchdog puis arrête capture.sh, pipeline.py et tcpdump
#    restart  — Enchaîne stop puis start
#    status   — État des processus, mode de l'interface, compteurs, watchdog
#    logs     — 20 dernières lignes du log pipeline (/var/log/capteur.log)
#    watchdog — (appelé par cron chaque minute) relance un composant tombé si le
#               capteur est armé ; ne fait rien après un stop volontaire
#
#  Dépend de  : capture.sh, pipeline.py (dans /root/)
#               iw, ip (configuration interface), nohup, cron (watchdog)
#  Logs       : /var/log/capture.log (capture), /var/log/capteur.log (pipeline),
#               /var/log/capteur_watchdog.log (watchdog)
# =============================================================================
export PATH=/usr/sbin:/usr/bin:/sbin:/bin:$PATH

IFACE="wlx64d95401ebeb"
LOG_CAPTURE="/var/log/capture.log"
LOG_PIPELINE="/var/log/capteur.log"
LOG_WATCHDOG="/var/log/capteur_watchdog.log"
PID_DIR="/var/run"

# Drapeau d'état persistant : présent ⇔ le capteur est CENSÉ tourner. Le watchdog
# ne relance JAMAIS quoi que ce soit si ce drapeau est absent → un `stop` volontaire
# n'est jamais combattu (cf. ancien crash-loop documenté en mémoire projet).
ENABLED_FLAG="/data/capture/.capteur_enabled"

# --- Push des trames intéressantes vers le poste de dev (scp UP²→PC) ----------
# Surchargeable sans toucher au script : créer /root/capteur.env avec
#   TRAMES_DEST="user@ip:/chemin/trames/"
# Laisser TRAMES_DEST vide désactive le push (la pipeline tourne sans).
[ -f /root/capteur.env ] && . /root/capteur.env
TRAMES_DEST="${TRAMES_DEST:-2039nngy@100.64.115.128:/home/2039nngy/Documents/PROJECT/WIFIEmbarquer/trames/}"
TRAMES_SSH_KEY="${TRAMES_SSH_KEY:-/root/.ssh/trames_push}"
export TRAMES_DEST TRAMES_SSH_KEY

precharger_modele() {
    # Charge le modèle LLM AVANT le trafic réel pour absorber le cold-start
    # (chargement Ollama > 60s) qui, sinon, ferait timeouter — donc rater — le
    # tout premier appareil ambigu après un (re)démarrage. keep_alive permanent
    # (cf. llm_analyzer.precharger) → le modèle reste résident ensuite.
    echo "  Préchargement du modèle LLM (absorbe le cold-start)..."
    if ! curl -s -o /dev/null -m 3 localhost:11434/api/tags; then
        echo "  ⚠ Ollama injoignable — préchargement ignoré (1er cas ambigu = risque de timeout)."
        return
    fi
    if python3 /root/llm_analyzer.py; then
        echo "  Modèle préchargé et épinglé en mémoire."
    else
        echo "  ⚠ Préchargement échoué — le 1er cas ambigu pourrait timeouter."
    fi
}

# --- Watchdog : relance automatique si un composant meurt -----------------------
WD_CRON="* * * * * /bin/bash /root/capteur.sh watchdog >> $LOG_WATCHDOG 2>&1"

installer_watchdog_cron() {
    # Idempotent : n'ajoute la ligne que si absente. Nécessite le service cron.
    if ! crontab -l 2>/dev/null | grep -qF "capteur.sh watchdog"; then
        ( crontab -l 2>/dev/null; echo "$WD_CRON" ) | crontab -
        echo "  Watchdog installé (cron, vérification chaque minute)"
    else
        echo "  Watchdog déjà installé (cron)"
    fi
}

desinstaller_watchdog_cron() {
    crontab -l 2>/dev/null | grep -vF "capteur.sh watchdog" | crontab - 2>/dev/null || true
}

# Surveille capture.sh (le SUPERVISEUR persistant — pas tcpdump, qui est relancé
# toutes les 30s et créerait des faux « down ») et pipeline.py. Relance le composant
# manquant ; si les DEUX sont absents (ex. après reboot), fait un start complet
# (remonte le mode monitor + préchauffe le modèle).
watchdog() {
    [ -f "$ENABLED_FLAG" ] || exit 0          # capteur arrêté volontairement → ne rien faire
    local ts; ts=$(date '+%Y-%m-%d %H:%M:%S')
    local pipe_up cap_up
    pgrep -f "/root/pipeline.py" >/dev/null && pipe_up=1 || pipe_up=0
    pgrep -f "/root/capture.sh"  >/dev/null && cap_up=1  || cap_up=0

    [ "$pipe_up" = 1 ] && [ "$cap_up" = 1 ] && exit 0    # tout va bien

    if [ "$pipe_up" = 0 ] && [ "$cap_up" = 0 ]; then
        echo "[$ts] watchdog: capteur entièrement à l'arrêt → start complet"
        start
        return
    fi
    if [ "$pipe_up" = 0 ]; then
        # Le modèle reste résident (keep_alive permanent) → relance directe, pas de
        # préchauffe. `9>&-` : ne pas léguer le verrou à l'enfant longue-durée.
        echo "[$ts] watchdog: pipeline.py absent → relance"
        nohup python3 /root/pipeline.py > "$LOG_PIPELINE" 2>&1 9>&- &
        echo $! > "$PID_DIR/capteur_pipeline.pid"
    fi
    if [ "$cap_up" = 0 ]; then
        echo "[$ts] watchdog: capture.sh absent → relance"
        pkill -f "channel_hop" 2>/dev/null    # évite un channel_hop orphelin en double
        nohup bash /root/capture.sh > "$LOG_CAPTURE" 2>&1 9>&- &
        echo $! > "$PID_DIR/capteur_capture.pid"
    fi
}

start() {
    if pgrep -f "pipeline.py" > /dev/null; then
        echo "Déjà en cours d'exécution."
        status
        exit 0
    fi

    echo "Démarrage du capteur WiFi..."

    # Mode monitor
    ip link set "$IFACE" down
    iw dev "$IFACE" set type monitor
    ip link set "$IFACE" up
    if [ "$(iw dev "$IFACE" info 2>/dev/null | grep 'type' | awk '{print $2}')" != "monitor" ]; then
        echo "ERREUR : impossible de passer $IFACE en mode monitor."
        exit 1
    fi
    echo "  Interface $IFACE en mode monitor"

    # Dossiers
    mkdir -p /data/capture/raw /data/capture/done /data/capture/interesting

    # Marque le capteur comme « censé tourner » + arme le watchdog (auto-restart).
    touch "$ENABLED_FLAG"
    installer_watchdog_cron

    # Nettoie les pycache
    find /root -name "*.pyc" -delete 2>/dev/null

    # Lance la capture. `9>&-` ferme le fd du verrou dans l'enfant : sinon le
    # processus longue-durée hériterait du flock et le tiendrait à vie → plus aucun
    # watchdog ne pourrait l'acquérir (bug attrapé au test R1).
    nohup bash /root/capture.sh > "$LOG_CAPTURE" 2>&1 9>&- &
    echo $! > "$PID_DIR/capteur_capture.pid"
    sleep 2

    # Précharge le modèle pendant que la capture remplit sa 1re fenêtre (30s),
    # de sorte que la pipeline démarre sur un modèle déjà chaud.
    precharger_modele

    # Lance la pipeline (idem : fd du verrou fermé dans l'enfant).
    nohup python3 /root/pipeline.py > "$LOG_PIPELINE" 2>&1 9>&- &
    echo $! > "$PID_DIR/capteur_pipeline.pid"
    sleep 1

    echo "  Capture   → PID $(cat $PID_DIR/capteur_capture.pid)"
    echo "  Pipeline  → PID $(cat $PID_DIR/capteur_pipeline.pid)"
    echo ""
    echo "Capteur démarré. Logs :"
    echo "  tail -f $LOG_CAPTURE"
    echo "  tail -f $LOG_PIPELINE"
}

stop() {
    echo "Arrêt du capteur WiFi..."
    # D'ABORD désarmer le watchdog : retirer le drapeau (sinon il relancerait tout)
    # puis désinstaller le cron — un `stop` doit être définitif.
    rm -f "$ENABLED_FLAG"
    desinstaller_watchdog_cron
    echo "  Watchdog désarmé"
    pkill -f "pipeline.py"   && echo "  Pipeline arrêtée"   || echo "  Pipeline déjà arrêtée"
    pkill -f "capture.sh"    && echo "  Capture arrêtée"    || echo "  Capture déjà arrêtée"
    pkill    "tcpdump"       && echo "  tcpdump arrêté"     || echo "  tcpdump déjà arrêté"
    pkill -f "channel_hop"  2>/dev/null
    rm -f "$PID_DIR/capteur_capture.pid" "$PID_DIR/capteur_pipeline.pid"
    sleep 1
    echo "Capteur arrêté."
}

status() {
    echo "=== État du capteur ==="
    if pgrep -f "pipeline.py" > /dev/null; then
        echo "  Pipeline  : EN MARCHE (PID $(pgrep -f pipeline.py))"
    else
        echo "  Pipeline  : ARRÊTÉE"
    fi
    if pgrep tcpdump > /dev/null; then
        echo "  Capture   : EN MARCHE (PID $(pgrep tcpdump))"
        iface_mode=$(iw dev "$IFACE" info 2>/dev/null | grep "type" | awk '{print $2}')
        echo "  Interface : $IFACE ($iface_mode)"
    else
        echo "  Capture   : ARRÊTÉE"
    fi
    echo ""
    RAW=$(ls /data/capture/raw/*.pcap 2>/dev/null | wc -l)
    DONE=$(ls /data/capture/done/*.pcap 2>/dev/null | wc -l)
    INTERESTING=$(ls /data/capture/interesting/*.pcap 2>/dev/null | wc -l)
    echo "  Fichiers raw        : $RAW"
    echo "  Fichiers traités    : $DONE"
    echo "  Captures suspectes  : $INTERESTING"
    if [ -f "$ENABLED_FLAG" ] && crontab -l 2>/dev/null | grep -qF "capteur.sh watchdog"; then
        echo "  Watchdog            : ARMÉ (auto-restart actif)"
    else
        echo "  Watchdog            : désarmé"
    fi
    if [ "$INTERESTING" -gt 0 ]; then
        echo ""
        echo "  Dernière capture suspecte :"
        ls -lht /data/capture/interesting/*.pcap | head -1 | awk '{print "    "$NF, $5, $6, $7, $8}'
    fi
}

logs() {
    echo "=== Pipeline (dernières lignes) ==="
    tail -20 "$LOG_PIPELINE"
}

# --- Verrou anti-double-démarrage --------------------------------------------
# Sérialise start/restart/watchdog : une seule (re)mise en marche à la fois. Sans
# lui, un tick watchdog pendant la préchauffe (~80s) de `start` relancerait la
# pipeline EN DOUBLE (cf. ancien crash-loop documenté). `stop` attend le verrou
# (jusqu'à 90s) avant de tuer, pour ne pas laisser un watchdog « en vol » relancer
# les processus après l'arrêt.
LOCK="/var/run/capteur.lock"
exec 9>"$LOCK"
case "$1" in
    start|restart|watchdog)
        flock -n 9 || { echo "capteur.sh: opération déjà en cours (verrou) — abandon."; exit 0; } ;;
    stop)
        flock -w 90 9 || true ;;
esac

case "$1" in
    start)    start  ;;
    stop)     stop   ;;
    restart)  stop; sleep 2; start ;;
    status)   status ;;
    logs)     logs   ;;
    watchdog) watchdog ;;   # appelé par cron chaque minute — relance ce qui est tombé
    *)
        echo "Usage: $0 {start|stop|restart|status|logs|watchdog}"
        exit 1
        ;;
esac
