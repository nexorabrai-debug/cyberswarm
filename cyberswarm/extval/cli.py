"""cyberswarm hacker validate|labs|ui  (1.1 validação externa)."""
import json, os, sys, time
from concurrent.futures import ThreadPoolExecutor
from .labs import LABS, status
def summary_rows(results):
    rows = []
    for r in results:
        m = r.get("metricas")
        if not m: rows.append(f"{r['lab']:15s} {r['mode']:4s} NÃO EXECUTADO: {r.get('erro')}"); continue
        rows.append(f"{r['lab']:15s} {r['mode']:4s} itens={m['itens_oficiais']:3d} detectados={m['detectados']:3d} revocação={m['revocacao']:.3f} "
                    f"achados={m['achados']:3d} mapeados={m['achados_mapeados']:3d} não-listados={m['confirmados_nao_listados']:3d} "
                    f"não-reproduzidos={m['nao_reproduzidos']:3d} prec.estrita={(m['precisao_estrita'] or 0):.3f} t={r['segundos']}s")
    return rows
def validate_all(labs, modes, out, use_nuclei=True, use_mobsf=True, parallel=True):
    from .runner import run_lab
    jobs = [(l, m) for l in labs for m in modes]
    def one(x):
        l, m = x; return run_lab(l, os.path.join(out, f"{l}-{m}"), mode=m, use_nuclei=use_nuclei, use_mobsf=use_mobsf)
    t0 = time.monotonic()
    with ThreadPoolExecutor(max_workers=len(jobs) if parallel else 1) as ex: res = [r for r, _ in ex.map(one, jobs)]
    return res, round(time.monotonic() - t0, 2)
def extval_main(a):
    if a.action == "labs":
        for n, l in LABS.items(): print(f"{n:15s} {status(n):15s} {l.get('url') or l.get('apk') or l.get('reason')}")
        return 0
    if a.action == "ui":
        from .ui import serve
        return serve(a.out, port=a.ui_port)
    labs = [n for n in LABS if LABS[n]["kind"] != "skip"] if a.lab == "all" else a.lab.split(",")
    modes = ["1.0", "1.1"] if a.mode == "both" else [a.mode]
    res, secs = validate_all(labs, modes, a.out, not a.no_nuclei, not a.no_mobsf)
    if a.lab == "all": res.append({"lab": "crapi", "mode": "-", "erro": LABS["crapi"]["reason"]})
    for r in summary_rows(res): print(r)
    json.dump({"resultados": [r for r in res], "segundos_total": secs}, open(os.path.join(a.out, "extval_summary.json"), "w"), indent=1, ensure_ascii=False, default=str)
    if not a.no_pdf:
        from .report_ext import demo_report
        print("relatório:", demo_report(a.out, res, a.pdf_path))
    return 0
