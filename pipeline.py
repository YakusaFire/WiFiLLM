#!/usr/bin/env python3
# =============================================================================
#  pipeline.py — Orchestrateur principal de la chaîne d'analyse WiFi
# =============================================================================
#  Rôle       : Surveille /data/capture/raw/ en boucle (toutes les 5 s) et
#               traite chaque nouveau pcap en enchaînant quatre étapes :
#                 1. prefilter   — extraction des trames suspectes (sans LLM)
#                 2. aggregateur — regroupement par MAC + classification auto
#                 3. llm_analyzer — analyse LLM pour les cas ambigus seulement
#                 4. extractor   — export du pcap filtré + JSON dans interesting/
#               Un Traqueur partagé maintient la mémoire inter-pcap des appareils
#               et un RegistreAP persistant la carte SSID→BSSID (détection evil_twin).
#               Les pcap traités sont déplacés dans /data/capture/done/.
#
#  Entrées    : /data/capture/raw/*.pcap  (produits par capture.sh)
#  Sorties    : /data/capture/interesting/*.pcap + *_analyse.json
#               /data/capture/done/*.pcap (archives)
#
#  Dépend de  : prefilter.py, aggregateur.py, llm_analyzer.py, extractor.py,
#               traqueur.py, registre_ap.py, tshark, Ollama (localhost:11434)
#  Lancé par  : capteur.sh start (via nohup en arrière-plan)
#  Log        : /var/log/capteur.log
# =============================================================================

import os
import glob
import time
import logging
from prefilter import filtrer_pcap
from aggregateur import agreger
from llm_analyzer import analyser
from extractor import extraire
from envoi_trames import pousser
from traqueur import Traqueur
from registre_ap import RegistreAP

CAPTURE_DIR = "/data/capture/raw"
ARCHIVE_DIR = "/data/capture/done"
os.makedirs(ARCHIVE_DIR, exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(message)s",
    datefmt="%H:%M:%S",
    handlers=[
        logging.FileHandler("/var/log/capteur.log"),
        logging.StreamHandler()
    ]
)

def traiter(pcap_path: str, traqueur: Traqueur | None = None,
            registre: RegistreAP | None = None):
    logging.info(f"→ {os.path.basename(pcap_path)}")

    if registre is not None:
        registre.nouvelle_fenetre()

    candidats = filtrer_pcap(pcap_path)
    if not candidats:
        logging.info("  Aucun candidat")
        os.rename(pcap_path, os.path.join(ARCHIVE_DIR, os.path.basename(pcap_path)))
        return

    agregats = agreger(candidats, traqueur, registre)
    logging.info(f"  {len(candidats)} trame(s) → {len(agregats)} appareil(s)")

    interessants = []

    for agr in agregats:
        auto = agr["auto_class"]

        if auto is not None:
            # Classifié sans LLM
            if auto["interesting"]:
                niveau = auto["threat_level"]
                cat    = auto["category"]
                raison = auto["reason"]
                logging.info(f"  ⚡ [{niveau}] {cat} — {raison}")
                for f in agr["frames"]:
                    f["analyse"] = auto
                    interessants.append(f)
            else:
                logging.info(f"  ✗ ignoré ({agr['mac']}) — {auto['reason']}")
        else:
            # Cas ambigu → LLM
            analyse = analyser(agr["description"])
            if analyse.get("interesting"):
                niveau = analyse["threat_level"]
                cat    = analyse["category"]
                logging.info(f"  ✓ [{niveau}] {cat} ({agr['mac']}) — {analyse.get('reason', '')}")
                for f in agr["frames"]:
                    f["analyse"] = analyse
                    interessants.append(f)
            else:
                logging.info(f"  ✗ [{analyse['threat_level']}] {analyse['category']} ({agr['mac']})")

    if interessants:
        out = extraire(pcap_path, interessants)
        if out:
            logging.info(f"  Extrait → {os.path.basename(out)}")
            json_path = out.replace(".pcap", "_analyse.json")
            if pousser(out, json_path):
                logging.info(f"  Envoyé → trames/ ({os.path.basename(out)} + json)")
    else:
        logging.info("  Aucune trame intéressante")

    if registre is not None:
        registre.sauver()

    os.rename(pcap_path, os.path.join(ARCHIVE_DIR, os.path.basename(pcap_path)))


def main():
    logging.info("Pipeline démarré")
    traites  = set()
    traqueur = Traqueur()
    registre = RegistreAP()

    while True:
        traqueur.nettoyer()
        registre.purger()
        fichiers = sorted(glob.glob(os.path.join(CAPTURE_DIR, "*.pcap")))
        for f in fichiers:
            if f not in traites:
                try:
                    traiter(f, traqueur, registre)
                except Exception as e:
                    logging.error(f"  ERREUR sur {os.path.basename(f)} : {e}")
                traites.add(f)
        time.sleep(5)


if __name__ == "__main__":
    main()
