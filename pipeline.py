#!/usr/bin/env python3

import os
import glob
import time
import logging
from prefilter import filtrer_pcap
from llm_analyzer import analyser
from extractor import extraire

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

def traiter(pcap_path: str):
    logging.info(f"→ {os.path.basename(pcap_path)}")

    candidats = filtrer_pcap(pcap_path)
    if not candidats:
        logging.info(f"  Aucun candidat")
        os.rename(pcap_path, os.path.join(ARCHIVE_DIR, os.path.basename(pcap_path)))
        return

    logging.info(f"  {len(candidats)} candidat(s) → LLM")

    interessants = []
    for c in candidats:
        analyse = analyser(c["description"])
        c["analyse"] = analyse
        if analyse.get("interesting"):
            niveau = analyse.get("threat_level", "?")
            categorie = analyse.get("category", "?")
            logging.info(f"  ✓ [{niveau}] {categorie} — {analyse.get('reason', '')}")
            interessants.append(c)

    if interessants:
        out = extraire(pcap_path, interessants)
        if out:
            logging.info(f"  Extrait → {os.path.basename(out)}")
    else:
        logging.info(f"  Aucune trame intéressante")

    os.rename(pcap_path, os.path.join(ARCHIVE_DIR, os.path.basename(pcap_path)))

def main():
    logging.info("Pipeline démarré")
    traites = set()

    while True:
        fichiers = sorted(glob.glob(os.path.join(CAPTURE_DIR, "*.pcap")))
        for f in fichiers:
            if f not in traites:
                try:
                    traiter(f)
                except Exception as e:
                    logging.error(f"  ERREUR sur {os.path.basename(f)} : {e}")
                traites.add(f)
        time.sleep(5)

if __name__ == "__main__":
    main()
