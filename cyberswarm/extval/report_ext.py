"""Combined 1.1 report (MD/HTML/PDF via the core report writer) with per-lab metric sections."""
import json, os, shutil
from ..db import DB
from ..report import write_reports
from .metrics import load_gt
def demo_report(out, results, pdf_path=None):
    db = DB(os.path.join(out, "extval_report.db")); rid = db.new_run("hacker-1.1-validacao-externa", None); extra = []
    rows = ["Laboratório | modo | itens oficiais | detectados | revocação | achados | mapeados | não listados | não reproduzidos | precisão estrita | tempo"]
    for r in results:
        m = r.get("metricas")
        if not m: rows.append(f"{r['lab']} | {r['mode']} | NÃO EXECUTADO: {r.get('erro','')[:120]}"); continue
        rows.append(f"{r['lab']} | {r['mode']} | {m['itens_oficiais']} | {m['detectados']} | {m['revocacao']:.1%} | {m['achados']} | {m['achados_mapeados']} | "
                    f"{m['confirmados_nao_listados']} | {m['nao_reproduzidos']} | {(m['precisao_estrita'] or 0):.1%} | {r['segundos']}s")
    extra.append(("Validação externa: métricas por laboratório (listas oficiais dos projetos)", rows + [
        "Revocação = itens oficiais com achado CONFIRMADO / total de itens oficiais (inclui desafios que exigem exploração ativa, que o CyberSwarm não faz).",
        "Nenhum número aqui significa cobertura total; cada laboratório mede só a si mesmo."]))
    seen = set()
    for r in results:
        m = r.get("metricas")
        if not m or r["mode"] != "1.1": continue
        names = {i["id"]: i["name"] for i in load_gt(r["lab"])["items"]}
        extra.append((f"{r['lab']}: detectados / não confirmados / não detectados", [f"Fonte oficial: {m['source']} ({m.get('version')})",
            "DETECTADOS: " + (", ".join(names[i] for i in m["itens_detectados"]) or "nenhum"),
            "APONTADOS SÓ POR FERRAMENTA (não reproduzidos, NÃO contam): " + (", ".join(f"{names.get(k,k)} ({', '.join(v)})" for k, v in m["itens_apontados_nao_confirmados"].items()) or "nenhum"),
            f"NÃO DETECTADOS ({m['nao_detectados']}): " + ", ".join(names[i] for i in m["itens_nao_detectados"]),
            "Confirmados fora da lista oficial: " + (", ".join(m["nao_listados"]) or "nenhum")]))
        data = json.load(open(os.path.join(out, f"{r['lab']}-1.1", f"extval_{r['lab']}_1.1.json")))
        for f in data["achados"]:
            if f["fingerprint"] in seen: continue
            seen.add(f["fingerprint"]); f["title"] = f"[{r['lab']}] " + f["title"]; db.add_finding(rid, f)
    rec = os.path.join(out, "recovery.json")
    if os.path.exists(rec):
        extra.append(("Recuperação de falhas e paralelismo", [f"{k}: {v}" for k, v in json.load(open(rec)).items()]))
    db.finish_run(rid)
    rd = os.path.join(out, "report"); write_reports(db, rid, rd, meta={"client_name": "Laboratórios educacionais externos (127.0.0.1)", "authorization_ref": "lab local"}, pdf=True, extra=extra)
    import glob
    pdfs = sorted(glob.glob(os.path.join(rd, "*.pdf")), key=os.path.getmtime); pdf = pdfs[-1] if pdfs else os.path.join(rd, "report.pdf")
    if pdf_path and os.path.exists(pdf): shutil.copy(pdf, pdf_path); return pdf_path
    return pdf
