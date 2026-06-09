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
#    start    — Mode monitor + création des dossiers + lancement capture & pipeline
#    stop     — Arrête proprement capture.sh, pipeline.py et tcpdump
#    restart  — Enchaîne stop puis start
#    status   — État des processus, mode de l'interface, compteurs de fichiers
#    logs     — 20 dernières lignes du log pipeline (/var/log/capteur.log)
#
#  Dépend de  : capture.sh, pipeline.py (dans /root/)
#               iw, ip (configuration interface), nohup
#  Logs       : /var/log/capture.log (capture), /var/log/capteur.log (pipeline)
# =============================================================================
export PATH=/usr/sbin:/usr/bin:/sbin:/bin:$PATH

IFACE="wlx64d95401ebeb"
LOG_CAPTURE="/var/log/capture.log"
LOG_PIPELINE="/var/log/capteur.log"
PID_DIR="/var/run"

# --- Push des trames intéressantes vers le poste de dev (scp UP²→PC) ----------
# Surchargeable sans toucher au script : créer /root/capteur.env avec
#   TRAMES_DEST="user@ip:/chemin/trames/"
# Laisser TRAMES_DEST vide désactive le push (la pipeline tourne sans).
[ -f /root/capteur.env ] && . /root/capteur.env
TRAMES_DEST="${TRAMES_DEST:-2039nngy@100.64.115.128:/home/2039nngy/Documents/PROJECT/WIFIEmbarquer/trames/}"
TRAMES_SSH_KEY="${TRAMES_SSH_KEY:-/root/.ssh/trames_push}"
export TRAMES_DEST TRAMES_SSH_KEY

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

    # Nettoie les pycache
    find /root -name "*.pyc" -delete 2>/dev/null

    # Lance la capture
    nohup bash /root/capture.sh > "$LOG_CAPTURE" 2>&1 &
    echo $! > "$PID_DIR/capteur_capture.pid"
    sleep 2

    # Lance la pipeline
    nohup python3 /root/pipeline.py > "$LOG_PIPELINE" 2>&1 &
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

case "$1" in
    start)  start  ;;
    stop)   stop   ;;
    restart) stop; sleep 2; start ;;
    status) status ;;
    logs)   logs   ;;
    *)
        echo "Usage: $0 {start|stop|restart|status|logs}"
        exit 1
        ;;
esac
