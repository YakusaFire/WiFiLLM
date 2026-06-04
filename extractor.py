#!/usr/bin/env python3
# =============================================================================
#  extractor.py — Extraction des trames retenues dans un pcap dédié + JSON
# =============================================================================
#  Rôle       : Pour chaque pcap contenant au moins une trame intéressante,
#               extrait exactement les trames concernées (par numéro de frame)
#               dans un nouveau fichier pcap via un filtre tshark, et génère
#               un fichier JSON d'analyse à côté.
#               Tolère le code de retour 2 de tshark (pcap tronqué en capture
#               live — les trames lues avant la coupure restent valides).
#
#  Entrée     : source_pcap (str) — chemin du pcap source
#               trames (list)     — liste de dicts {numero, description, layers,
#                                   analyse} produits par pipeline.py
#  Sortie     : /data/capture/interesting/<nom>_<timestamp>.pcap
#               /data/capture/interesting/<nom>_<timestamp>_analyse.json
#               Retourne le chemin du pcap créé, ou None en cas d'échec.
#
#  Dépend de  : tshark (subprocess)
#  Appelé par : pipeline.py
# =============================================================================

import subprocess
import os
import json
from datetime import datetime

OUTPUT_DIR = "/data/capture/interesting"
os.makedirs(OUTPUT_DIR, exist_ok=True)

def extraire(source_pcap: str, trames: list) -> str:
    if not trames:
        return None

    numeros = [t["numero"] for t in trames]
    filtre = " or ".join(f"frame.number=={n}" for n in numeros)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    nom_base = os.path.splitext(os.path.basename(source_pcap))[0]
    out_pcap = os.path.join(OUTPUT_DIR, f"{nom_base}_{timestamp}.pcap")
    out_json = out_pcap.replace(".pcap", "_analyse.json")

    r = subprocess.run(
        ["tshark", "-r", source_pcap, "-Y", filtre, "-w", out_pcap],
        capture_output=True
    )
    # Code 2 = pcap tronqué en capture live — acceptable, les trames lues sont valides
    if r.returncode not in (0, 2) or not os.path.exists(out_pcap):
        return None

    with open(out_json, "w") as f:
        json.dump(trames, f, indent=2, ensure_ascii=False)

    return out_pcap
