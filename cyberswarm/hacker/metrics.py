"""Performance evaluation vs. lab ground truth (precision / recall / F1, per module).
Ground truth = list of planted lab issues {check_id, target}; '{http}', '{https}', '{tcp_http}', '{tcp_https}' are
replaced by the lab URLs of the run. Matching: same check_id and same normalized target."""
import json, os
from ..scope import LABDATA
from ..agents.validation import normalize_target
GT_PATH = os.path.join(LABDATA, "ground_truth.json")
def load_gt(path=GT_PATH, subst=None):
    items = json.load(open(path, encoding="utf-8"))["items"]; out = []
    for it in items:
        t = it["target"]
        for k, v in (subst or {}).items(): t = t.replace("{" + k + "}", v)
        if t.startswith("labdata/"): t = os.path.join(LABDATA, t[len("labdata/"):])
        out.append({**it, "target": t})
    return out
def _match(g, f):
    return g["check_id"] == f["check_id"] and normalize_target(g["target"]) == normalize_target(f["target"]) and g.get("match", "") in f"{f['title']} {f['evidence']}"
def evaluate(findings, gt, modules=None):
    """Greedy one-to-one matching GT item <-> finding. modules: only GT items of modules that ran are counted."""
    gt = [g for g in gt if modules is None or g["module"] in modules]; used = set(); tp, fn = [], []
    for g in gt:
        i = next((i for i, f in enumerate(findings) if i not in used and _match(g, f)), None)
        if i is None: fn.append(g)
        else: used.add(i); tp.append((g, findings[i]))
    fp = [f for i, f in enumerate(findings) if i not in used]
    def pr(a, b): return round(a / b, 4) if b else None
    p, r = pr(len(tp), len(tp) + len(fp)), pr(len(tp), len(tp) + len(fn)); per = {}
    for g, _ in tp: per.setdefault(g["module"], [0, 0, 0])[0] += 1
    for f in fp: per.setdefault(f["agent"], [0, 0, 0])[1] += 1
    for g in fn: per.setdefault(g["module"], [0, 0, 0])[2] += 1
    return {"tp": len(tp), "fp": len(fp), "fn": len(fn), "precision": p, "recall": r,
            "f1": round(2 * p * r / (p + r), 4) if p and r else None,
            "per_module": {m: {"tp": a, "fp": b, "fn": c} for m, (a, b, c) in sorted(per.items())},
            "false_positives": [[f["check_id"], normalize_target(f["target"]) + " " + f["title"][-40:]] for f in fp],
            "false_negatives": [[g["check_id"], normalize_target(g["target"]) + (" " + g["match"] if g.get("match") else "")] for g in fn]}
