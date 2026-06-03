#!/bin/bash

MODEM_APN="free"
MODEM_IFACE="wwan0"
PCAP_DIR="/data/capture/interesting"
REMOTE_USER="user"
REMOTE_HOST="ton-serveur"
REMOTE_PATH="/data/pcap_incoming/"
MAX_WAIT=30

log() { echo "[$(date '+%H:%M:%S')] $1"; }

fichiers_a_envoyer() {
    find "$PCAP_DIR" -name "*.pcap" | wc -l
}

activer_4g() {
    log "Activation modem 4G..."
    sudo mmcli -m 0 --enable
    sudo mmcli -m 0 --simple-connect="apn=$MODEM_APN"

    local attente=0
    while ! ip addr show "$MODEM_IFACE" 2>/dev/null | grep -q "inet "; do
        sleep 2
        attente=$((attente + 2))
        if [ $attente -ge $MAX_WAIT ]; then
            log "ERREUR : pas de connexion après ${MAX_WAIT}s"
            return 1
        fi
    done

    local ip
    ip=$(ip addr show "$MODEM_IFACE" | grep "inet " | awk '{print $2}')
    log "Connecté — IP : $ip"
    return 0
}

envoyer() {
    log "Envoi de $(fichiers_a_envoyer) fichier(s)..."
    rsync -az --remove-source-files \
        "$PCAP_DIR"/*.pcap \
        "$REMOTE_USER@$REMOTE_HOST:$REMOTE_PATH"

    if [ $? -eq 0 ]; then
        log "Envoi terminé"
    else
        log "ERREUR pendant l'envoi"
        return 1
    fi
}

desactiver_4g() {
    log "Désactivation modem 4G..."
    sudo mmcli -m 0 --simple-disconnect
    sudo mmcli -m 0 --disable
    sudo ip link set "$MODEM_IFACE" down
    log "Modem éteint"
}

main() {
    if [ "$(fichiers_a_envoyer)" -eq 0 ]; then
        log "Aucun fichier à envoyer — abandon"
        exit 0
    fi

    log "$(fichiers_a_envoyer) fichier(s) en attente"

    if ! activer_4g; then
        desactiver_4g
        exit 1
    fi

    envoyer
    desactiver_4g
}

main
