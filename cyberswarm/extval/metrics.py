"""Metrics against OFFICIAL vulnerability lists. Definitions (see docs/VALIDACAO_EXTERNA.md):
- detectado (VP): official item with >=1 CONFIRMED finding mapped to it.   - não detectado (FN): the rest.
- achados confirmados não listados: reproduced evidence but not in the official list (real issue, not counted as VP).
- não reproduzido (FP de ferramenta): tool hit our validator could not reproduce (kept as 'suspeita', not reported as vuln).
- precisão estrita = achados mapeados / todos os achados;  precisão por evidência = confirmados / todos;  revocação = VP / itens oficiais."""
import json, os, re
D = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")
def load_gt(lab): return json.load(open(os.path.join(D, f"gt_{lab}.json")))
def load_map(lab): return json.load(open(os.path.join(D, "mapping.json"))).get(lab, [])
def items_for(f, rules):
    hits = []
    for r in rules:
        if "check" in r and f["check_id"] != r["check"]: continue
        if "template" in r and (f.get("template") or "") != r["template"]: continue
        if "mobsf" in r and not (f.get("tool") == "mobsf" and f.get("category") == r["mobsf"]): continue
        if "match" in r and r["match"] not in (f.get("target", "") + f.get("title", "") + f.get("evidence", "")): continue
        hits.append(r["item"])
    return sorted(set(hits))
def evaluate(lab, findings):
    gt = load_gt(lab); rules = load_map(lab); ids = [i["id"] for i in gt["items"]]
    det, mapped, unlisted, unrepro, per_src = {}, 0, [], [], {}
    for f in findings:
        src = f.get("tool") or f["agent"]; s = per_src.setdefault(src, {"achados": 0, "confirmados": 0, "mapeados": 0, "nao_reproduzidos": 0})
        s["achados"] += 1
        its = items_for(f, rules)
        if f["status"] != "confirmado":
            unrepro.append(f); s["nao_reproduzidos"] += 1; continue
        s["confirmados"] += 1
        if its:
            mapped += 1; s["mapeados"] += 1
            for i in its: det.setdefault(i, []).append(f["fingerprint"])
        else: unlisted.append(f)
    pend = {}
    for f in unrepro:
        for i in items_for(f, rules):
            if i not in det: pend.setdefault(i, set()).add(f.get("template") or f.get("rule") or f["check_id"])
    n = len(findings); tp = len([i for i in ids if i in det])
    by_src_items = {}
    for f in findings:
        if f["status"] == "confirmado":
            for i in items_for(f, rules): by_src_items.setdefault(f.get("tool") or f["agent"], set()).add(i)
    for k, v in per_src.items(): v["itens_oficiais_detectados"] = len(by_src_items.get(k, ()))
    return {"lab": lab, "source": gt["source"], "version": gt.get("version"), "itens_oficiais": len(ids), "detectados": tp,
            "nao_detectados": len(ids) - tp, "revocacao": round(tp / len(ids), 4) if ids else None,
            "achados": n, "achados_mapeados": mapped, "confirmados_nao_listados": len(unlisted), "nao_reproduzidos": len(unrepro),
            "precisao_estrita": round(mapped / n, 4) if n else None, "precisao_evidencia": round((n - len(unrepro)) / n, 4) if n else None,
            "itens_detectados": sorted(det), "itens_apontados_nao_confirmados": {k: sorted(v) for k, v in sorted(pend.items())}, "itens_nao_detectados": [i for i in ids if i not in det],
            "nao_listados": sorted({f["check_id"] + (f" [{f.get('template')}]" if f.get("template") else "") for f in unlisted}),
            "nao_reproduzidos_lista": sorted({(f.get("template") or f.get("rule") or f["check_id"]) for f in unrepro}),
            "por_fonte": per_src}
