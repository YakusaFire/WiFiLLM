#!/usr/bin/env python3
# =============================================================================
#  setup_push_trames.py — Déploiement du push trames UP²→PC (à lancer du PC)
# =============================================================================
#  Rôle       : Met en place (et resynchronise) le push scp des trames
#               intéressantes du UP² vers ce poste. À exécuter depuis le PC
#               de dev quand le UP² est en ligne (Tailscale). Idempotent.
#               Étapes :
#                 1. Connexion SSH au UP² avec les identifiants de .env
#                 2. Dépôt de la clé privée dédiée dans /root/.ssh/trames_push
#                 3. Sync du code à jour (envoi_trames.py, pipeline.py, capteur.sh)
#                 4. Vérification de la présence des fichiers
#               La clé PUBLIQUE correspondante doit déjà être dans le
#               ~/.ssh/authorized_keys de ce PC (fait par la mise en place).
#
#  Pré-requis : ~/.ssh/trames_push (clé privée) présent sur le PC
#               .env avec SSH_IP / SSH_USER / SSH_PASSWORD
#               paramiko installé (pip install paramiko)
#  Usage      : python3 scripts/setup_push_trames.py
# =============================================================================

import os
import sys
import paramiko

RACINE   = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CLE_PRIV = os.path.expanduser("~/.ssh/trames_push")

# Fichiers à pousser : (source locale, destination /root, mode octal)
A_DEPLOYER = [
    (CLE_PRIV,                             "/root/.ssh/trames_push", "600"),
    (os.path.join(RACINE, "envoi_trames.py"),     "/root/envoi_trames.py", "644"),
    (os.path.join(RACINE, "pipeline.py"),         "/root/pipeline.py",     "644"),
    (os.path.join(RACINE, "scripts/capteur.sh"),  "/root/capteur.sh",      "755"),
]


def charger_env(chemin):
    cfg = {}
    with open(chemin) as f:
        for ligne in f:
            ligne = ligne.strip()
            if ligne and not ligne.startswith("#") and "=" in ligne:
                k, v = ligne.split("=", 1)
                cfg[k.strip()] = v.strip()
    return cfg


def main():
    if not os.path.exists(CLE_PRIV):
        sys.exit(f"Clé privée absente : {CLE_PRIV} (relancer la mise en place).")

    env = charger_env(os.path.join(RACINE, ".env"))
    ip   = env["SSH_IP"]
    user = env["SSH_USER"]
    pwd  = env["SSH_PASSWORD"]

    print(f"Connexion à {user}@{ip} ...")
    cli = paramiko.SSHClient()
    cli.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    cli.connect(ip, username=user, password=pwd, timeout=15)

    def sudo(cmd):
        """Exécute une commande en root via sudo -S (mot de passe sur stdin)."""
        full = f"sudo -S -p '' bash -c {_quote(cmd)}"
        stdin, stdout, stderr = cli.exec_command(full)
        stdin.write(pwd + "\n")
        stdin.flush()
        code = stdout.channel.recv_exit_status()
        return code, stdout.read().decode(), stderr.read().decode()

    sftp = cli.open_sftp()
    sudo("mkdir -p /root/.ssh && chmod 700 /root/.ssh")

    for src, dst, mode in A_DEPLOYER:
        if not os.path.exists(src):
            print(f"  ⚠ source absente, ignorée : {src}")
            continue
        tmp = "/tmp/" + os.path.basename(dst)
        sftp.put(src, tmp)
        code, _, err = sudo(f"mv {tmp} {dst} && chown root:root {dst} && chmod {mode} {dst}")
        statut = "ok" if code == 0 else f"ÉCHEC ({err.strip()})"
        print(f"  {dst}  [{mode}]  → {statut}")

    sftp.close()

    # Vérification rapide
    code, out, _ = sudo("ls -l /root/.ssh/trames_push /root/envoi_trames.py /root/pipeline.py /root/capteur.sh")
    print("\nVérification côté UP² :")
    print(out.rstrip())
    cli.close()
    print("\nTerminé. Sur le UP² : su - puis  bash /root/capteur.sh restart")


def _quote(s):
    """Quote une commande pour 'bash -c'."""
    return "'" + s.replace("'", "'\\''") + "'"


if __name__ == "__main__":
    main()
