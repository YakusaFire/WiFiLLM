#!/usr/bin/env python3

import os
import glob
import time
import logging
from prefilter import filtrer_pcap
from aggregateur import agreger
from llm_analyzer import analyser
from extractor import extraire
from traqueur import Traqueur

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

def traiter(pcap_path: str, traqueur: Traqueur | None = None):
    logging.info(f"→ {os.path.basename(pcap_path)}")

    candidats = filtrer_pcap(pcap_path)
    if not candidats:
        logging.info("  Aucun candidat")
        os.rename(pcap_path, os.path.join(ARCHIVE_DIR, os.path.basename(pcap_path)))
        return

    agregats = agreger(candidats, traqueur)
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
    else:
        logging.info("  Aucune trame intéressante")

    os.rename(pcap_path, os.path.join(ARCHIVE_DIR, os.path.basename(pcap_path)))


def main():
    logging.info("Pipeline démarré")
    traites  = set()
    traqueur = Traqueur()

    while True:
        traqueur.nettoyer()
        fichiers = sorted(glob.glob(os.path.join(CAPTURE_DIR, "*.pcap")))
        for f in fichiers:
            if f not in traites:
                try:
                    traiter(f, traqueur)
                except Exception as e:
                    logging.error(f"  ERREUR sur {os.path.basename(f)} : {e}")
                traites.add(f)
        time.sleep(5)


if __name__ == "__main__":
    main()
