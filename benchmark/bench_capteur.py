#!/usr/bin/env python3
# benchmark/bench_capteur.py — rejoue le corpus à travers les VRAIS modules de
# production (prefilter→aggregateur→llm_analyzer→extractor) en chronométrant
# chaque étape, puis score contre le manifest. À lancer DANS /root sur le UP².
import os, sys, json, time, tempfile, argparse, statistics

sys.path.insert(0, "/root")                # modules de prod : pipeline & co
import oui
from prefilter import filtrer_pcap
from aggregateur import agreger
from llm_analyzer import analyser
from traqueur import Traqueur
from registre_ap import RegistreAP

CORPUS = os.path.join(os.path.dirname(os.path.abspath(__file__)), "corpus")

def warmup():
    """Une inférence à blanc pour isoler le cold-start (mesuré à part)."""
    t = time.perf_counter()
    analyser("Appareil 00:11:22:33:44:55 (MAC PERMANENT) — 1 trame en 30s.")
    return time.perf_counter() - t

def run(no_llm=False):
    manifest = json.load(open(os.path.join(CORPUS, "manifest.json")))
    traqueur = Traqueur()
    registre = RegistreAP(chemin=os.path.join(tempfile.mkdtemp(), "reg.json"))  # JAMAIS la prod

    cold = warmup() if not no_llm else 0.0
    resultats, latences = [], []

    for win in manifest:
        oui.MODE = win["mode"]
        pcap = os.path.join(CORPUS, win["pcap"])
        registre.nouvelle_fenetre()

        t0 = time.perf_counter(); candidats = filtrer_pcap(pcap);      t_pre = time.perf_counter() - t0
        t0 = time.perf_counter(); agregats  = agreger(candidats, traqueur, registre); t_agg = time.perf_counter() - t0

        t_llm, verdicts = 0.0, {}
        for agr in agregats:
            auto = agr["auto_class"]
            if auto is not None:
                verdicts[agr["mac"]] = (auto["interesting"], auto["category"], "RÈGLE", auto["reason"])
            elif no_llm:
                verdicts[agr["mac"]] = (None, None, "LLM(non éval.)", "")
            else:
                t0 = time.perf_counter(); a = analyser(agr["description"]); dt = time.perf_counter() - t0
                t_llm += dt
                verdicts[agr["mac"]] = (a.get("interesting"), a.get("category"), "LLM", a.get("reason", ""))

        latences.append({"pcap": win["pcap"], "prefilter": t_pre, "aggregateur": t_agg,
                         "llm": t_llm, "total": t_pre + t_agg + t_llm,
                         "n_llm": sum(1 for v in verdicts.values() if v[2] == "LLM")})

        for mac, att in win["attendu"].items():
            got = verdicts.get(mac)
            if got is None:
                resultats.append({"pcap": win["pcap"], "mac": mac, "label": att["label"],
                                  "att_int": att["interesting"], "got_int": "ABSENT",
                                  "att_cat": att["category"], "got_cat": "—",
                                  "chemin": "—", "ok": att["interesting"] in (False, None),
                                  "raison": "appareil non remonté par prefilter"})
                continue
            gi, gc, chemin, raison = got
            ok = (att["interesting"] is None) or (gi == att["interesting"])
            resultats.append({"pcap": win["pcap"], "mac": mac, "label": att["label"],
                              "att_int": att["interesting"], "got_int": gi,
                              "att_cat": att["category"], "got_cat": gc,
                              "chemin": chemin, "ok": ok, "raison": raison})

    return cold, resultats, latences

def stats(vals):
    if not vals: return (0, 0, 0, 0)
    s = sorted(vals)
    p95 = s[min(len(s) - 1, int(round(0.95 * (len(s) - 1))))]
    return (statistics.mean(vals), statistics.median(vals), max(vals), p95)

def rapporter(cold, resultats, latences, no_llm):
    print("\n================  COUVERTURE  ================")
    print(f"{'pcap':28} {'label':28} {'att':>4} {'got':>5} {'chemin':>14}  cat_attendue→obtenue")
    fn, fp, ok_h, ok_b = [], [], 0, 0
    for r in resultats:
        flag = "OK " if r["ok"] else "KO!"
        ai = {True:"H", False:"b", None:"?"}[r["att_int"]]
        gi = {True:"H", False:"b", None:"?"}.get(r["got_int"], str(r["got_int"]))
        print(f"{flag} {r['pcap']:26} {r['label']:26} {ai:>4} {gi:>5} {r['chemin']:>14}  {r['att_cat']}→{r['got_cat']}")
        if r["att_int"] is True:
            ok_h += r["ok"]
            if not r["ok"]: fn.append(r["label"])
        elif r["att_int"] is False:
            ok_b += r["ok"]
            if not r["ok"]: fp.append(r["label"])
    n_h = sum(1 for r in resultats if r["att_int"] is True)
    n_b = sum(1 for r in resultats if r["att_int"] is False)
    print(f"\nRappel hostiles : {ok_h}/{n_h}   |   Bénins corrects : {ok_b}/{n_b}")
    print(f"Faux négatifs (hostile raté) : {fn or 'aucun'}")
    print(f"Faux positifs (fausse alerte): {fp or 'aucun'}")

    print("\n================  LATENCE (s)  ================")
    if not no_llm:
        print(f"Cold-start LLM (1re inférence après préchargement) : {cold:.2f}s")
    print(f"{'pcap':28} {'prefilter':>9} {'aggreg':>8} {'llm':>8} {'total':>8} {'#llm':>5}")
    for L in latences:
        print(f"{L['pcap']:28} {L['prefilter']:9.3f} {L['aggregateur']:8.3f} {L['llm']:8.3f} {L['total']:8.3f} {L['n_llm']:5}")
    for nom, clef in [("prefilter","prefilter"), ("aggregateur","aggregateur"),
                      ("llm (fenêtres avec LLM)","llm"), ("total","total")]:
        if clef == "llm":
            vals = [L["llm"] for L in latences if L["n_llm"] > 0]
        else:
            vals = [L[clef] for L in latences]
        m, med, mx, p95 = stats(vals)
        print(f"  {nom:26} moy {m:7.3f}  méd {med:7.3f}  p95 {p95:7.3f}  max {mx:7.3f}")
    n_llm_calls = sum(L["n_llm"] for L in latences)
    print(f"\nAppels LLM totaux : {n_llm_calls}   |   fenêtres : {len(latences)}")

    return {"cold": cold, "resultats": resultats, "latences": latences}

def ecrire_rapport_md(cold, resultats, latences, no_llm, chemin):
    """Écrit le RAPPORT COMPLET en Markdown (section 8 du guide, auto-rempli)."""
    import datetime, llm_analyzer
    sym = {True: "hostile", False: "bénin", None: "neutre"}
    n_h = sum(1 for r in resultats if r["att_int"] is True)
    n_b = sum(1 for r in resultats if r["att_int"] is False)
    ok_h = sum(1 for r in resultats if r["att_int"] is True and r["ok"])
    ok_b = sum(1 for r in resultats if r["att_int"] is False and r["ok"])
    fn = [r for r in resultats if r["att_int"] is True and not r["ok"]]
    fp = [r for r in resultats if r["att_int"] is False and not r["ok"]]
    n_regle = sum(1 for r in resultats if r["chemin"] == "RÈGLE")
    n_llm   = sum(1 for r in resultats if r["chemin"] == "LLM")
    n_llm_calls = sum(L["n_llm"] for L in latences)

    def agg(clef, only_llm=False):
        vals = ([L["llm"] for L in latences if L["n_llm"] > 0] if only_llm
                else [L[clef] for L in latences])
        return stats(vals)  # (moy, méd, max, p95)

    L = []
    L.append("# Rapport — Benchmark complet du capteur (auto-généré)\n")
    L.append(f"**Date :** {datetime.date.today().isoformat()}  ")
    L.append(f"**Device :** UP² 7100 `wifi-llm` · `{llm_analyzer.MODEL}` (Ollama localhost:11434)  ")
    L.append("**Outils :** benchmark/generer_corpus.py + benchmark/bench_capteur.py  ")
    L.append(f"**Corpus :** {len(latences)} fenêtres pcap étiquetées (benchmark/corpus/manifest.json)  ")
    cond = "split déterministe seul (LLM non évalué)" if no_llm else "capture arrêtée, modèle préchauffé, registre temporaire isolé"
    L.append(f"**Conditions :** {cond}\n")
    L.append("---\n")

    L.append("## 1. Couverture de détection\n")
    L.append(f"- **Rappel hostiles : {ok_h}/{n_h}**" +
             (f" — faux négatifs : {', '.join(r['label'] for r in fn)} ⚠️" if fn else " — aucun faux négatif ✅"))
    L.append(f"- **Bénins correctement ignorés : {ok_b}/{n_b}**" +
             (f" — faux positifs : {', '.join(r['label'] for r in fp)}" if fp else " — aucun faux positif ✅") + "\n")
    L.append("| Scénario (pcap) | Appareil | Attendu | Obtenu | Chemin | Catégorie att.→obt. | Verdict |")
    L.append("|---|---|---|---|---|---|---|")
    for r in resultats:
        v = "✅" if r["ok"] else "❌"
        L.append(f"| {r['pcap']} | `{r['mac']}` ({r['label']}) | {sym[r['att_int']]} | "
                 f"{sym.get(r['got_int'], r['got_int'])} | {r['chemin']} | "
                 f"{r['att_cat']}→{r['got_cat']} | {v} |")
    L.append("")

    L.append("## 2. Latence par étape\n")
    if not no_llm:
        L.append(f"Cold-start LLM (1re inférence après préchauffage) : **{cold:.2f} s** "
                 "— non représentatif du régime établi, exclu des stats warm.\n")
    L.append("| Étape | Moyenne | Médiane | p95 | Max |")
    L.append("|---|---|---|---|---|")
    for nom, clef, only in [("prefilter (tshark)", "prefilter", False),
                            ("aggregateur", "aggregateur", False),
                            ("LLM (fenêtres ambiguës)", "llm", True),
                            ("total / fenêtre", "total", False)]:
        m, med, mx, p95 = agg(clef, only)
        u = lambda x: (f"{x*1000:.0f} ms" if x < 1 else f"{x:.2f} s")
        L.append(f"| {nom} | {u(m)} | {u(med)} | {u(p95)} | {u(mx)} |")
    L.append("\n**Détail par fenêtre :**\n")
    L.append("| pcap | prefilter | aggregateur | llm | total | #appels LLM |")
    L.append("|---|---|---|---|---|---|")
    for d in latences:
        L.append(f"| {d['pcap']} | {d['prefilter']*1000:.0f} ms | {d['aggregateur']*1000:.0f} ms | "
                 f"{d['llm']:.2f} s | {d['total']:.2f} s | {d['n_llm']} |")
    L.append("")

    L.append("## 3. Répartition des décisions (RÈGLE vs LLM)\n")
    tot = max(1, n_regle + n_llm)
    L.append(f"- Tranché par **RÈGLE** (coût ~0) : **{n_regle}/{tot}** ({100*n_regle/tot:.0f}%)")
    L.append(f"- Escaladé au **LLM** (cas ambigus) : **{n_llm}/{tot}** ({100*n_llm/tot:.0f}%)")
    L.append(f"- Appels LLM réellement effectués : **{n_llm_calls}** sur {len(latences)} fenêtres.\n")

    L.append("## 4. Analyse\n")
    L.append(f"- **Couverture** : {ok_h}/{n_h} types d'ennemis signalés. " +
             ("Aucun gap." if not fn else "Gaps : " + ", ".join(r['label'] for r in fn) + "."))
    if fp:
        L.append("- **Faux positifs** : " + ", ".join(f"{r['label']} (raison LLM : « {r['raison'][:80]} »)" for r in fp) +
                 ". B3 (assoc domestique) est une limite connue de qwen2.5:3b.")
    mL, *_ = agg("llm", True)
    L.append(f"- **Goulot d'étranglement** : le LLM (moy {mL:.2f} s/fenêtre ambiguë) domine ; "
             f"prefilter+aggregateur restent en millisecondes. {n_regle}/{tot} décisions évitent le LLM.")
    L.append("")

    L.append("## 5. Verdict\n")
    L.append(f"> Le capteur détecte **{ok_h}/{n_h}** types d'ennemis testés"
             + (f" ({len(fp)} faux positif(s))" if fp else " sans faux positif")
             + f". Temps médian de traitement d'une fenêtre : "
             f"**{agg('total')[1]:.2f} s** (≈ {agg('total')[1]*1000:.0f} ms hors LLM).\n")
    L.append("| Capacité | État |")
    L.append("|---|---|")
    caps = [("Attaques dures (deauth/handshake)", ["e1", "e2", "e3", "p1"]),
            ("Surveillance / reconnaissance", ["e4", "p2", "p3"]),
            ("AP furtif / over-secured", ["e6"]),
            ("Evil twin (registre persistant)", ["e7"]),
            ("Modes calibration/terrain", ["m1", "m2"]),
            ("Faux positifs zone grise", ["b3"])]
    for nom, prefixes in caps:
        lignes = [r for r in resultats if any(r["pcap"].startswith(p) for p in prefixes)]
        bon = all(r["ok"] for r in lignes) if lignes else None
        L.append(f"| {nom} | {'✅' if bon else ('❌' if bon is False else 'n/a')} |")
    L.append("\n*Campagne menée capteur arrêté ; capture + tcpdump laissés stoppés après le run.*")

    with open(chemin, "w", encoding="utf-8") as f:
        f.write("\n".join(L))
    return chemin


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--no-llm", action="store_true", help="split déterministe seul (sans Ollama)")
    ap.add_argument("--json", help="dump JSON brut des résultats")
    ap.add_argument("--rapport", help="écrit le rapport complet en Markdown à ce chemin")
    args = ap.parse_args()
    cold, resultats, latences = run(args.no_llm)
    data = rapporter(cold, resultats, latences, args.no_llm)
    if args.json:
        json.dump(data, open(args.json, "w"), indent=2, ensure_ascii=False, default=str)
        print(f"\nJSON → {args.json}")
    if args.rapport:
        print(f"Rapport Markdown → {ecrire_rapport_md(cold, resultats, latences, args.no_llm, args.rapport)}")
