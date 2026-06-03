#!/bin/bash
export PATH=/usr/sbin:/usr/bin:/sbin:/bin:$PATH

IFACE="wlx64d95401ebeb"
CAPTURE_DIR="/data/capture/raw"
ROTATION_SECONDES=30
ROTATION_TAILLE_MO=20
CHANNELS_24="1 2 3 4 5 6 7 8 9 10 11"
CHANNELS_5="36 40 44 48 52 56 60 64 100 104 108 112 116 120 124 128 132 136 140"

log() { echo "[$(date '+%H:%M:%S')] $1"; }

verifier_interface() {
    if ! ip link show "$IFACE" &>/dev/null; then
        log "ERREUR : interface $IFACE introuvable"
        log "Interfaces disponibles :"
        ip link show | grep -E "^[0-9]" | awk '{print "  " $2}'
        exit 1
    fi
}

activer_monitor() {
    log "Passage de $IFACE en mode monitor..."
    ip link set "$IFACE" down
    iw dev "$IFACE" set type monitor
    ip link set "$IFACE" up

    local mode
    mode=$(iw dev "$IFACE" info 2>/dev/null | grep "type" | awk '{print $2}')
    if [ "$mode" != "monitor" ]; then
        log "ERREUR : impossible de passer en mode monitor (mode actuel : $mode)"
        exit 1
    fi
    log "Mode monitor actif"
}

channel_hop() {
    log "Channel hopping démarré en arrière-plan"
    while true; do
        for ch in $CHANNELS_24 $CHANNELS_5; do
            iw dev "$IFACE" set channel "$ch" 2>/dev/null
            sleep 0.3
        done
    done
}

capturer() {
    mkdir -p "$CAPTURE_DIR"
    log "Capture démarrée → $CAPTURE_DIR"
    log "Rotation : toutes les ${ROTATION_SECONDES}s ou ${ROTATION_TAILLE_MO}Mo"
    log "Appuie sur Ctrl+C pour arrêter"

    local ts
    while true; do
        ts=$(date '+%Y%m%d_%H%M%S')
        timeout "$ROTATION_SECONDES" tcpdump -i "$IFACE" \
            -f "type mgt or type data" \
            -w "$CAPTURE_DIR/raw_${ts}.pcap" \
            -q 2>/dev/null
    done
}

nettoyer() {
    log "Arrêt demandé"
    kill "$CHANNEL_HOP_PID" 2>/dev/null
    exit 0
}

trap nettoyer SIGINT SIGTERM

verifier_interface
activer_monitor

channel_hop &
CHANNEL_HOP_PID=$!

capturer
