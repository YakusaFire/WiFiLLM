#!/usr/bin/env python3
# =============================================================================
#  test_registre_ap.py — Tests unitaires du registre persistant des AP
# =============================================================================
#  Rôle : Valide, SANS réseau ni tshark/Ollama, la logique qui sous-tend la
#         détection d'evil twin :
#           - antériorité (le 1er BSSID vu d'un SSID = référence légitime)
#           - détection de conflit (nouveau BSSID sur SSID établi ; cas E1
#             « même fenêtre » au démarrage à froid)
#           - absence de faux conflit (BSSID unique ; mesh tout-connu stable)
#           - persistance disque (sauver → recharger = même état)
#           - purge des AP trop anciens
#
#  Exécution : python3 test_registre_ap.py   (autonome, local)
# =============================================================================

import os
import time
import tempfile

from registre_ap import RegistreAP, SEUIL_ALERTE_FENETRES

V, R, RST, G, GR = "\033[92m", "\033[91m", "\033[0m", "\033[1m", "\033[90m"

_res = []
def check(nom, cond, detail=""):
    _res.append(bool(cond))
    tag = f"{V}OK{RST}" if cond else f"{R}KO{RST}"
    print(f"  [{tag}] {nom}")
    if detail:
        print(f"        {GR}{detail}{RST}")

# MACs de référence
LEGIT = "80:20:da:aa:aa:aa"   # Sagemcom (box légitime)
ROGUE = "00:de:ad:be:ef:00"   # OUI bidon (pirate)
AP2   = "80:20:da:bb:bb:bb"   # même vendor que LEGIT (répéteur mesh légitime)

def infos(vendor="Sagemcom", canal="6", secu="WPA2-PSK", score=1, signal=-60):
    return {"vendor": vendor, "canal": canal,
            "profil_secu": secu, "score_secu": score, "signal_max": signal}


def t_anteriorite_et_conflit_prod():
    print(f"\n{G}1. Antériorité + conflit (registre déjà peuplé){RST}")
    r = RegistreAP(chemin=os.path.join(tempfile.mkdtemp(), "reg.json"))

    # LEGIT établi sur 5 fenêtres
    for _ in range(5):
        r.nouvelle_fenetre()
        st = r.observer("Wifi_Cafe", LEGIT, infos(signal=-68))
    check("LEGIT seul → 'premier_du_ssid'", st == "premier_du_ssid", f"statut={st}")
    check("LEGIT a bien cumulé 5 fenêtres", r._aps["Wifi_Cafe"][LEGIT]["n_fenetres"] == 5)

    # ROGUE apparaît en fenêtre 6, signal fort, OUI inconnu
    r.nouvelle_fenetre()
    st = r.observer("Wifi_Cafe", ROGUE, infos(vendor=None, canal="11", secu="ouvert", score=0, signal=-30))
    check("ROGUE nouveau sur SSID établi → 'conflit'", st == "conflit", f"statut={st}")

    desc = r.description_comparative("Wifi_Cafe")
    check("Description comparative non vide", bool(desc))
    check("Réf = LEGIT marqué ANTÉRIEUR", "ANTÉRIEUR" in desc and LEGIT in desc)
    check("ROGUE marqué NOUVEAU VENU", "NOUVEAU VENU" in desc and ROGUE in desc)
    check("Signaux comparés présents (-68 et -30)", "-68" in desc and "-30" in desc)
    print(f"     {GR}{desc[:240]}{RST}")


def t_conflit_meme_fenetre_E1():
    print(f"\n{G}2. Conflit « même fenêtre » (démarrage à froid — cas E1){RST}")
    r = RegistreAP(chemin=os.path.join(tempfile.mkdtemp(), "reg.json"))
    r.nouvelle_fenetre()
    st1 = r.observer("Wifi_Cafe", LEGIT, infos(signal=-68))
    st2 = r.observer("Wifi_Cafe", ROGUE, infos(vendor=None, secu="ouvert", signal=-30))
    check("1er beacon → 'premier_du_ssid'", st1 == "premier_du_ssid", f"statut={st1}")
    check("2e beacon même SSID, BSSID ≠ → 'conflit'", st2 == "conflit", f"statut={st2}")
    check("Comparaison liste les 2 BSSID", LEGIT in r.description_comparative("Wifi_Cafe")
          and ROGUE in r.description_comparative("Wifi_Cafe"))


def t_pas_de_faux_conflit():
    print(f"\n{G}3. Pas de faux conflit (BSSID unique ; mesh tout-connu stable){RST}")
    r = RegistreAP(chemin=os.path.join(tempfile.mkdtemp(), "reg.json"))

    # SSID neuf, un seul BSSID → jamais de conflit
    for _ in range(3):
        r.nouvelle_fenetre()
        st = r.observer("MaBox", LEGIT, infos())
    check("BSSID unique → jamais 'conflit'", st != "conflit", f"statut={st}")
    check("Description vide si <2 BSSID", r.description_comparative("MaBox") == "")

    # Mesh : 2 BSSID même vendor, tous deux vus longtemps (au-delà du seuil d'alerte)
    r2 = RegistreAP(chemin=os.path.join(tempfile.mkdtemp(), "reg.json"))
    for _ in range(SEUIL_ALERTE_FENETRES + 3):
        r2.nouvelle_fenetre()
        r2.observer("Entreprise", LEGIT, infos(signal=-55))
        r2.observer("Entreprise", AP2, infos(signal=-58))
    r2.nouvelle_fenetre()
    st = r2.observer("Entreprise", AP2, infos(signal=-58))
    check("Mesh stabilisé (n_fenetres > seuil) → 'connu', pas 'conflit'",
          st == "connu", f"statut={st}  (n_fen AP2={r2._aps['Entreprise'][AP2]['n_fenetres']})")


def t_persistance():
    print(f"\n{G}4. Persistance disque (sauver → recharger){RST}")
    chemin = os.path.join(tempfile.mkdtemp(), "reg.json")
    r = RegistreAP(chemin=chemin)
    for _ in range(4):
        r.nouvelle_fenetre()
        r.observer("Wifi_Cafe", LEGIT, infos(signal=-68))
    r.nouvelle_fenetre()
    r.observer("Wifi_Cafe", ROGUE, infos(vendor=None, signal=-30))
    r.sauver()
    check("Fichier JSON écrit", os.path.exists(chemin))

    r2 = RegistreAP(chemin=chemin)  # recharge
    check("SSID rechargé", "Wifi_Cafe" in r2.ssids())
    check("2 BSSID rechargés", set(r2.bssids("Wifi_Cafe")) == {LEGIT, ROGUE})
    check("n_fenetres LEGIT préservé (=4)", r2._aps["Wifi_Cafe"][LEGIT]["n_fenetres"] == 4)
    check("Compteur de fenêtre repris au-dessus du max mémorisé",
          r2._fenetre >= r._aps["Wifi_Cafe"][ROGUE]["derniere_fenetre"],
          f"_fenetre rechargé={r2._fenetre}")

    # Après rechargement, ROGUE n'est plus « nouveau venu » (déjà connu) →
    # ré-observer LEGIT ne doit pas re-déclencher de conflit via la référence.
    r2.nouvelle_fenetre()
    st = r2.observer("Wifi_Cafe", LEGIT, infos(signal=-68))
    check("Réf ré-observée après reload → pas 'conflit'", st != "conflit", f"statut={st}")


def t_purge():
    print(f"\n{G}5. Purge des AP trop anciens{RST}")
    r = RegistreAP(chemin=os.path.join(tempfile.mkdtemp(), "reg.json"))
    r.nouvelle_fenetre()
    r.observer("Vieux", LEGIT, infos())
    r.observer("Frais", ROGUE, infos())
    # Vieillit artificiellement LEGIT de 30 jours
    r._aps["Vieux"][LEGIT]["derniere_vue"] = time.time() - 30 * 86400
    r.purger(max_age_jours=14)
    check("SSID périmé purgé", "Vieux" not in r.ssids())
    check("SSID frais conservé", "Frais" in r.ssids())


if __name__ == "__main__":
    print(f"{G}{'='*64}{RST}")
    print(f"{G}  TESTS — registre_ap.py (logique evil_twin, hors LLM){RST}")
    print(f"{G}{'='*64}{RST}")
    t_anteriorite_et_conflit_prod()
    t_conflit_meme_fenetre_E1()
    t_pas_de_faux_conflit()
    t_persistance()
    t_purge()
    n_ok, n = sum(_res), len(_res)
    print(f"\n{G}{'='*64}{RST}")
    coul = V if n_ok == n else R
    print(f"{coul}  BILAN : {n_ok}/{n} assertions vertes{RST}")
    print(f"{G}{'='*64}{RST}")
    raise SystemExit(0 if n_ok == n else 1)
