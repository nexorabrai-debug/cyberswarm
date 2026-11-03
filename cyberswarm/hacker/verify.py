"""Independent verification + hypothesis re-evaluation.
Step A (reproduction): every 'confirmado' finding is re-produced by RE-RUNNING its module in a fresh context (new Net,
new request budget) - the fingerprint and a valid proof must appear again, otherwise it is downgraded to 'suspeita'.
Step B (corroboration): where a DIFFERENT tool exists (sslyze for TLS, checkov for Terraform, a second SAST engine for
code), it is run and recorded as corroborated_by. Corroboration never upgrades on its own; it is reported."""
import asyncio, json, os, subprocess, tempfile
from urllib.parse import urlparse
from ..agents.validation import validate, proof_status, validate_severity, PRIORITY
from ..agents.codesec import ast_scan, bandit_scan, semgrep_scan
from ..tools import which
from ..agents.common import display_path
def rerun(agent_cls, ctx, target):
    return {f["fingerprint"]: f for f in validate(asyncio.run(agent_cls(ctx).run(target)))}
def sslyze_check(url):
    u = urlparse(url); out = tempfile.mktemp(suffix=".json")
    subprocess.run([which("sslyze"), "--tlsv1", "--tlsv1_1", "--http_headers", f"--json_out={out}", f"{u.hostname}:{u.port or 443}"], capture_output=True, text=True, timeout=180)
    d = json.load(open(out)); os.unlink(out); r = d["server_scan_results"][0]["scan_result"]; res = {}
    acc = lambda k: bool(((r.get(k) or {}).get("result") or {}).get("accepted_cipher_suites"))
    res["tls.old_protocol"] = acc("tls_1_0_cipher_suites") or acc("tls_1_1_cipher_suites")
    hh = (r.get("http_headers") or {}).get("result")
    if hh is not None: res["tls.hsts"] = hh.get("strict_transport_security_header") is None
    return res
def checkov_lines(path):
    r = subprocess.run([which("checkov"), "-d" if os.path.isdir(path) else "-f", path, "-o", "json", "--quiet", "--compact", "--framework", "terraform", "--skip-download"],
                       capture_output=True, text=True, timeout=300)
    d = json.loads(r.stdout or "{}"); d = d if isinstance(d, list) else [d]; hits = []
    for blk in d:
        for c in (blk.get("results") or {}).get("failed_checks", []):
            hits.append((os.path.realpath(c.get("file_abs_path", "")), c["file_line_range"][0], c["file_line_range"][1], c["check_id"]))
    return hits
def sast_lines(tool, path):
    if tool == "bandit": return {(os.path.realpath(p), ln, cid) for p, ln, cid, _ in bandit_scan(path)}
    if tool == "semgrep": return {(os.path.realpath(p), ln, cid) for p, ln, cid, _ in semgrep_scan(path)}
    out = set()
    for root, _, fs in os.walk(path) if os.path.isdir(path) else [(os.path.dirname(path), [], [os.path.basename(path)])]:
        for f in fs:
            if f.endswith(".py"): p = os.path.realpath(os.path.join(root, f)); out |= {(p, ln, cid) for ln, cid in ast_scan(open(p, errors="ignore").read())}
    return out
def verify_all(findings, agents, make_ctx, selected, bus=None, memory=None, rid=None):
    """Mutates findings: adds f['verification']; downgrades non-reproduced. Returns summary dict."""
    from .selector import select_verifier
    groups = {}
    for f in findings: groups.setdefault((f["agent"], f.get("task_target", f["target"])), []).append(f)
    summary = {"checked": 0, "reproduced": 0, "downgraded": 0, "corroborated": 0, "tools": {}, "errors": []}
    for (agent, ttarget), fs in groups.items():
        conf = [f for f in fs if f["status"] == "confirmado"]
        for f in fs:
            if f["status"] != "confirmado": f["verification"] = {"reproduced": None, "method": "não verificado: sem evidência reproduzível", "corroborated_by": None}
        if not conf: continue
        try: again = rerun(agents[agent], make_ctx(), ttarget)
        except Exception as e: again = {}; summary["errors"].append(f"{agent}: {e!r}"[:200])
        corr = {}; vtool = select_verifier(agent if agent in ("tls", "cloud", "codesec") else "-", selected.get(agent))
        try:
            if vtool == "sslyze": corr = {k: v for k, v in sslyze_check(ttarget).items()}
            elif vtool == "checkov": corr = {"_lines": checkov_lines(ttarget)}
            elif agent == "codesec": corr = {"_sast": sast_lines(vtool.replace("builtin-ast", "builtin"), ttarget)}
        except Exception as e: summary["errors"].append(f"{vtool}: {e!r}"[:200]); vtool = "builtin-rerun"
        summary["tools"][agent] = vtool
        for f in conf:
            summary["checked"] += 1; g = again.get(f["fingerprint"]); ok = bool(g) and proof_status(g.get("proof")) == "confirmado"
            cb = None
            if vtool == "sslyze" and corr.get(f["check_id"]): cb = "sslyze"
            if vtool == "checkov" and f["proof"].get("type") == "file":
                ln, ab = f["proof"]["line"], f["proof"].get("abs")
                ids = [c for p, a, b, c in corr["_lines"] if p == ab and a <= ln <= b]
                if ids: cb = "checkov " + ",".join(sorted(set(ids))[:3])
            if agent == "codesec" and (os.path.realpath(f["target"]), f["proof"].get("line"), f["check_id"]) in corr.get("_sast", set()): cb = vtool
            f["verification"] = {"reproduced": ok, "method": "re-execução independente do módulo (novo contexto/orçamento)", "corroborated_by": cb}
            if ok: summary["reproduced"] += 1
            else:
                f["status"] = "suspeita"; f["severity"] = validate_severity(f); f["priority"] = PRIORITY[f["severity"]]; summary["downgraded"] += 1
            if cb: summary["corroborated"] += 1
            if bus: bus.publish("verification", "verifier", {"fingerprint": f["fingerprint"], "reproduced": ok, "corroborated_by": cb})
    return summary
def reevaluate_hypotheses(findings, memory, rid, bus=None, ran=None):
    """Each 'suspeita' becomes/updates a hypothesis; hypotheses from PREVIOUS runs are re-evaluated against this run."""
    by_fp = {f["fingerprint"]: f for f in findings}; changes = []
    for h in memory.hypotheses(status="aberta"):
        if h["run_id"] == rid or not h["key"].startswith("fp:"): continue
        _, agent, fp = h["key"].split(":", 2)
        if ran is not None and agent not in ran: continue  # module not executed now: cannot judge
        f = by_fp.get(fp)
        if f is None: memory.update_hypothesis(h["id"], "descartada", f"não observada na execução {rid}"); changes.append((h["id"], "descartada"))
        elif f["status"] == "confirmado": memory.update_hypothesis(h["id"], "confirmada", f"evidência reproduzida na execução {rid}"); changes.append((h["id"], "confirmada"))
    for f in findings:
        if f["status"] == "suspeita":
            hid = memory.add_hypothesis(rid, f"fp:{f['agent']}:{f['fingerprint']}", f"{f['check_id']} em {display_path(f['target']) if '://' not in f['target'] else f['target']}", "aberta", f.get("verification", {}).get("method", ""))
            if bus: bus.publish("hypothesis", "verifier", {"id": hid, "fingerprint": f["fingerprint"], "status": "aberta"})
    return changes
