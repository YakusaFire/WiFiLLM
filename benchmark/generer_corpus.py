#!/usr/bin/env python3
# benchmark/generer_corpus.py — fabrique un corpus de pcap 802.11 étiquetés.
# Dépend de scapy. Sortie : benchmark/corpus/*.pcap + benchmark/corpus/manifest.json
import os, json, struct
from scapy.all import (RadioTap, Dot11, Dot11Beacon, Dot11ProbeReq, Dot11Deauth,
                       Dot11Auth, Dot11AssoReq, Dot11Elt, LLC, SNAP, wrpcap)
from scapy.layers.eap import EAPOL

ICI = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(ICI, "corpus")
os.makedirs(OUT, exist_ok=True)

BCAST = "ff:ff:ff:ff:ff:ff"

# --- MACs de référence (alignées sur tests/test_batterie.py) -----------------
PERM   = "00:11:22:33:44:55"   # permanent générique
RPI    = "b8:27:eb:11:22:33"   # Raspberry Pi (permanent)
ESP    = "08:3a:8d:11:22:33"   # Espressif (deauther probable)
GLINET = "94:83:c4:11:22:33"   # GL Technologies (matériel maison)
SAGEM  = "80:20:da:aa:aa:aa"   # Sagemcom (box légitime — référence evil twin)
ROGUE  = "00:de:ad:be:ef:00"   # AP pirate (evil twin)
PHONE1 = "da:a1:19:7c:00:01"   # randomisé (bit 0x02) — vie privée
PHONE2 = "c6:2b:88:40:11:02"   # randomisé
FILAT  = "ee:88:c1:7f:33:44"   # randomisé MAIS persistant → filature
MESH_A = "80:20:da:11:11:11"   # Sagemcom — nœud mesh A
MESH_B = "80:20:da:22:22:22"   # Sagemcom — nœud mesh B (MÊME fabricant → mesh)

def rt(signal):
    """RadioTap avec dBm_AntSignal renseigné (→ radiotap.dbm_antsignal)."""
    try:
        return RadioTap(dBm_AntSignal=signal)
    except Exception:                      # vieux scapy : present explicite
        return RadioTap(present="dBm_AntSignal", dBm_AntSignal=signal)

def rsn_ie(akm=2, pcs=4, group=4, mfpr=False, mfpc=False):
    """Octets d'un Information Element RSN (ID 48). akm/pcs/group = derniers
    octets de la suite 00-0f-ac-X. WPA2-PSK akm=2 ; WPA3-SAE akm=8 ;
    CCMP-128 pcs=4 ; GCMP-256 pcs=9. MFPR=bit6, MFPC=bit7 des RSN caps."""
    OUIB = b"\x00\x0f\xac"
    caps = (0x0040 if mfpr else 0) | (0x0080 if mfpc else 0)
    return (struct.pack("<H", 1) + OUIB + bytes([group]) +
            struct.pack("<H", 1) + OUIB + bytes([pcs]) +
            struct.pack("<H", 1) + OUIB + bytes([akm]) +
            struct.pack("<H", caps))

# --- Fabriques de trames -----------------------------------------------------
def deauth(sa, da, signal=-40, bssid=None):
    bssid = bssid or sa
    return rt(signal)/Dot11(type=0, subtype=12, addr1=da, addr2=sa, addr3=bssid)/Dot11Deauth(reason=7)

def probe(sa, ssid="", signal=-60):
    p = rt(signal)/Dot11(type=0, subtype=4, addr1=BCAST, addr2=sa, addr3=BCAST)/Dot11ProbeReq()
    return p/Dot11Elt(ID=0, info=ssid.encode())

def auth(sa, bssid=PERM, signal=-30):
    return rt(signal)/Dot11(type=0, subtype=11, addr1=bssid, addr2=sa, addr3=bssid)/Dot11Auth(seqnum=1)

def assoc(sa, ssid, bssid=PERM, signal=-67):
    p = rt(signal)/Dot11(type=0, subtype=0, addr1=bssid, addr2=sa, addr3=bssid)/Dot11AssoReq()
    return p/Dot11Elt(ID=0, info=ssid.encode())

def eapol(sa, bssid=PERM, signal=-41):
    # Trame Data (type=2, subtype=0) portant un EAPOL-Key (type=3) via LLC/SNAP
    # 0x888e → tshark voit eapol.type. ToDS=FromDS=0 : addr2 = wlan.sa.
    return (rt(signal)/Dot11(type=2, subtype=0, addr1=bssid, addr2=sa, addr3=bssid)/
            LLC(dsap=0xaa, ssap=0xaa, ctrl=3)/SNAP(OUI=0, code=0x888e)/
            EAPOL(version=2, type=3))

def beacon(bssid, ssid, channel=6, signal=-60, secure=False, masked=False, interval=100):
    cap = "ESS+privacy" if (secure or not masked) else "ESS"
    elts = Dot11Elt(ID=0, info=(b"" if masked else ssid.encode()))
    elts /= Dot11Elt(ID=3, info=bytes([channel]))            # DS Parameter Set
    if secure:                                               # RSN WPA3-SAE+GCMP256+PMF
        elts /= Dot11Elt(ID=48, info=rsn_ie(akm=8, pcs=9, mfpr=True, mfpc=True))
    else:                                                    # RSN WPA2-PSK banal
        elts /= Dot11Elt(ID=48, info=rsn_ie(akm=2, pcs=4))
    return (rt(signal)/Dot11(type=0, subtype=8, addr1=BCAST, addr2=bssid, addr3=bssid)/
            Dot11Beacon(cap=cap, beacon_interval=interval)/elts)

# --- Bruit civil réutilisable ------------------------------------------------
def bruit_civil():
    return [probe(PHONE1, "", -58), probe(PHONE2, "Maison_5G", -61),
            beacon("80:20:da:bb:bb:bb", "Livebox-2A30", channel=6, signal=-65)]

# --- Construction du corpus : (nom_pcap, [trames], {mac: attendu}) ------------
# attendu = {"interesting": bool, "category": str|None, "label": str}
# (Le capteur opère toujours en posture terrain — plus de mode calibration.)
WINDOWS = []
def W(nom, trames, attendu):
    WINDOWS.append({"pcap": nom, "trames": trames, "attendu": attendu})

# E1 deauth broadcast (×8)
W("e1_deauth_broadcast", [deauth(PERM, BCAST, -38) for _ in range(8)] + bruit_civil(),
  {PERM: {"interesting": True, "category": "deauth_attack", "label": "Deauth broadcast"}})
# E2 deauth ciblé (×4)
W("e2_deauth_cible", [deauth(PERM, "44:65:0d:99:88:77", -46) for _ in range(4)] + bruit_civil(),
  {PERM: {"interesting": True, "category": "deauth_attack", "label": "Deauth ciblé"}})
# E3 handshake EAPOL (×3)
W("e3_handshake", [eapol(PERM, signal=-41) for _ in range(3)] + bruit_civil(),
  {PERM: {"interesting": True, "category": "handshake", "label": "Handshake WPA"}})
# E4 surveillance : permanent sonde 6 SSID
W("e4_surveillance", [probe(RPI, f"Box-{c}", -52) for c in "ABCDEF"] + bruit_civil(),
  {RPI: {"interesting": True, "category": "surveillance", "label": "Recon multi-SSID"}})
# E5 probe_tracking : permanent vise 1 SSID sensible + auth, signal fort (→ LLM)
W("e5_probe_tracking",
  [probe(PERM, "MINDEF_OPS_5G", -29), probe(PERM, "MINDEF_OPS_5G", -30), auth(PERM, signal=-29)] + bruit_civil(),
  {PERM: {"interesting": True, "category": None, "label": "Tracking SSID sensible"}})
# E6 over_secured / covert_ap : beacon WPA3+PMF, SSID masqué, signal très fort (→ LLM)
W("e6_over_secured", [beacon(PERM, "", channel=36, signal=-24, secure=True, masked=True)] + bruit_civil(),
  {PERM: {"interesting": True, "category": None, "label": "AP sur-sécurisé furtif"}})
# E8 anomaly : auth en rafale sans assoc ni probe, signal fort (atypique → LLM)
W("e8_anomaly", [auth(RPI, signal=-33) for _ in range(4)] + bruit_civil(),
  {RPI: {"interesting": None, "category": None, "label": "Anomalie (auth en rafale)"}})

# E7 evil twin : 4 fenêtres SAGEM établi puis 1 fenêtre ROGUE même SSID, signal fort.
for i in range(1, 5):
    W(f"e7_evil_twin_{i}_legit", [beacon(SAGEM, "Wifi_Cafe", channel=6, signal=-68)],
      {SAGEM: {"interesting": False, "category": "normal", "label": "AP légitime (réf)"}})
W("e7_evil_twin_5_rogue",
  [beacon(SAGEM, "Wifi_Cafe", channel=6, signal=-68), beacon(ROGUE, "Wifi_Cafe", channel=11, signal=-30)],
  {ROGUE: {"interesting": True, "category": "evil_twin", "label": "Evil twin (rogue)"},
   SAGEM: {"interesting": False, "category": "normal", "label": "AP légitime (réf)"}})

# Bénins
W("b1_civil_randomise", [probe(PHONE1, "", -58), probe(PHONE2, "Cafe_Centre", -61)],
  {PHONE1: {"interesting": False, "category": "normal", "label": "iPhone vie privée"},
   PHONE2: {"interesting": False, "category": "normal", "label": "Android vie privée"}})
W("b2_box_internet", [beacon("80:20:da:bb:bb:bb", "Livebox-2A30", channel=6, signal=-65)],
  {"80:20:da:bb:bb:bb": {"interesting": False, "category": "normal", "label": "Box WPA2"}})
W("b3_assoc_domestique", [auth(PERM, signal=-70), assoc(PERM, "Livebox-2A30", signal=-69)],
  {PERM: {"interesting": False, "category": "normal", "label": "Assoc domestique (zone grise)"}})

# Pièges
W("p1_glinet_deauth", [deauth(GLINET, BCAST, -40) for _ in range(6)],
  {GLINET: {"interesting": True, "category": "deauth_attack", "label": "Ami fait un deauth"}})
W("p2_surveillance_4ssid", [probe(RPI, f"Z{i}", -55) for i in range(4)],
  {RPI: {"interesting": True, "category": "surveillance", "label": "Permanent sonde 4 SSID (surveillance, règle)"}})
W("p3_esp_probe", [probe(ESP, "", -50) for _ in range(3)],
  {ESP: {"interesting": True, "category": None, "label": "ESP sonde (deauther ?)"}})
W("p4_glinet_zone", [probe(GLINET, f"AP{i}", -55) for i in range(6)],
  {GLINET: {"interesting": True, "category": None, "label": "GL.iNet (infra domestique) sonde 6 SSID"}})

# MESH : 2 AP même SSID, MÊME fabricant (Sagemcom) — infra multi-AP, suspect en
# zone (catégorie déterministe 'mesh'). Multi-fenêtres : en 1re fenêtre, le 2e AP
# traité est levé (le 1er n'a pas encore de jumeau au registre) ; en régime établi
# (fenêtre suivante), les DEUX sont levés.
W("mesh_1_2ap", [beacon(MESH_A, "Bureau_Mesh", channel=6, signal=-55),
                 beacon(MESH_B, "Bureau_Mesh", channel=11, signal=-58)],
  {MESH_B: {"interesting": True,  "category": "mesh",   "label": "Mesh nœud B (1re fenêtre)"},
   MESH_A: {"interesting": False, "category": "normal", "label": "Mesh nœud A (bénin 1re fenêtre)"}})
W("mesh_2_2ap", [beacon(MESH_A, "Bureau_Mesh", channel=6, signal=-55),
                 beacon(MESH_B, "Bureau_Mesh", channel=11, signal=-58)],
  {MESH_A: {"interesting": True, "category": "mesh", "label": "Mesh nœud A (régime établi)"},
   MESH_B: {"interesting": True, "category": "mesh", "label": "Mesh nœud B (régime établi)"}})

# Filature : même MAC randomisée sur 4 fenêtres → escalade traqueur, doit rester bénin
for i in range(1, 5):
    W(f"f1_filature_{i}", [probe(FILAT, "Hotel_Lobby", -44)],
      {FILAT: {"interesting": False, "category": "normal", "label": "Filature randomisée (<=benin)"}})

# --- Écriture ----------------------------------------------------------------
manifest = []
for w in WINDOWS:
    chemin = os.path.join(OUT, w["pcap"] + ".pcap")
    wrpcap(chemin, w["trames"])
    manifest.append({"pcap": w["pcap"] + ".pcap", "attendu": w["attendu"]})

with open(os.path.join(OUT, "manifest.json"), "w") as f:
    json.dump(manifest, f, indent=2, ensure_ascii=False)

print(f"{len(WINDOWS)} pcap générés dans {OUT}")
print(f"manifest.json écrit ({len(manifest)} fenêtres)")
