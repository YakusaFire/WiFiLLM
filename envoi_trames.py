#!/usr/bin/env python3
# =============================================================================
#  envoi_trames.py — Push scp des trames intéressantes vers le poste de dev
# =============================================================================
#  Rôle       : Juste après extraction, pousse vers le PC de dev (sens UP²→PC)
#               le pcap filtré (uniquement les trames intéressantes) et son
#               JSON d'analyse, par scp sur clé SSH dédiée. Déclenché à
#               l'événement « ce pcap contient des trames intéressantes ».
#               Conçu pour ne JAMAIS casser la pipeline : tout échec (réseau
#               coupé, PC éteint, clé absente) est journalisé puis ignoré.
#               No-op silencieux si TRAMES_DEST n'est pas configuré.
#
#  Entrée     : chemins de fichiers (pcap + json) à envoyer
#  Sortie     : fichiers déposés dans TRAMES_DEST (ex: PC:.../trames/)
#               la source côté UP² n'est PAS supprimée (interesting/ = archive)
#
#  Configuration (variables d'environnement, posées par capteur.sh) :
#    TRAMES_DEST        destination scp, ex:
#                       "2039nngy@100.64.115.128:/home/2039nngy/.../trames/"
#                       vide ou absente → push désactivé (no-op)
#    TRAMES_SSH_KEY     clé privée pour l'auth UP²→PC (défaut /root/.ssh/trames_push)
#    TRAMES_SCP_TIMEOUT délai max de connexion scp en secondes (défaut 20)
#
#  Dépend de  : scp (openssh-client)
#  Appelé par : pipeline.py
# =============================================================================

import os
import subprocess
import logging

DEST    = os.environ.get("TRAMES_DEST", "").strip()
SSH_KEY = os.environ.get("TRAMES_SSH_KEY", "/root/.ssh/trames_push").strip()
TIMEOUT = int(os.environ.get("TRAMES_SCP_TIMEOUT", "20"))


def pousser(*chemins) -> bool:
    """scp les fichiers donnés vers TRAMES_DEST. Ne lève jamais.

    Retourne True si l'envoi a réussi, False si désactivé, sans fichier
    valide, ou en cas d'échec (journalisé en warning)."""
    fichiers = [c for c in chemins if c and os.path.exists(c)]
    if not DEST or not fichiers:
        return False

    cmd = ["scp", "-q",
           "-o", "BatchMode=yes",
           "-o", "StrictHostKeyChecking=accept-new",
           "-o", f"ConnectTimeout={TIMEOUT}"]
    if SSH_KEY and os.path.exists(SSH_KEY):
        cmd += ["-i", SSH_KEY]
    cmd += fichiers + [DEST]

    try:
        r = subprocess.run(cmd, capture_output=True, timeout=TIMEOUT + 30)
        if r.returncode == 0:
            return True
        err = r.stderr.decode(errors="replace").strip()
        logging.warning(f"  envoi trames : scp code {r.returncode} — {err}")
        return False
    except subprocess.TimeoutExpired:
        logging.warning("  envoi trames : timeout scp")
        return False
    except Exception as e:
        logging.warning(f"  envoi trames : {e}")
        return False
