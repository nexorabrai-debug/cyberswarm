"""Threat Intelligence (offline CWE/ATT&CK/OWASP-LLM + small version->CVE table) and Vulnerability Research
(per-finding notes + attack-chain correlation). No network access."""
import json, os, re
DATA = os.path.join(os.path.dirname(__file__), "data", "threat_intel.json")
def load(): return json.load(open(DATA, encoding="utf-8"))
def threat_intel(findings, ti=None):
    """Adds f['intel'] = {cwe:[{id,name}], attack:[...], owasp_llm:[...], cves:[...]}; returns number enriched."""
    ti = ti or load(); n = 0
    for f in findings:
        refs = f.get("refs", []); cwe = [{"id": r, "name": ti["cwe"][r]["name"]} for r in refs if r in ti["cwe"]]
        attack = sorted({a for r in refs if r in ti["cwe"] for a in ti["cwe"][r]["attack"]} | {r for r in refs if re.match(r"T\d{4}", r)})
        llm = [f"{r} {ti['owasp_llm'][r]}" for r in refs if r in ti["owasp_llm"]]
        cves = [{"cve": v["cve"], "summary": v["summary"]} for v in ti["versions"] if re.search(v["product_regex"], f.get("evidence", ""))]
        f["intel"] = {"cwe": cwe, "attack": attack, "owasp_llm": llm, "cves": cves}
        n += bool(cwe or attack or llm or cves)
    return n
def _has(alts, ids): return any(a in ids for a in alts.split("|"))
def vuln_research(findings, ti=None):
    """Per-finding research note + correlated attack chains (only from CONFIRMED findings)."""
    ti = ti or load(); conf = {f["check_id"] for f in findings if f["status"] == "confirmado"}
    for f in findings:
        i = f.get("intel", {}); parts = []
        if i.get("cwe"): parts.append("Classe: " + "; ".join(f"{c['id']} {c['name']}" for c in i["cwe"]))
        if i.get("attack"): parts.append("ATT&CK: " + ", ".join(i["attack"]))
        if i.get("owasp_llm"): parts.append("OWASP LLM: " + ", ".join(i["owasp_llm"]))
        if i.get("cves"): parts.append("CVE (base offline): " + ", ".join(c["cve"] for c in i["cves"]))
        parts.append("Status: " + ("confirmado com evidência reproduzida" if f["status"] == "confirmado" else "hipótese - precisa de verificação manual"))
        f["research"] = " | ".join(parts)
    chains = [{"name": c["name"], "narrative": c["narrative"], "evidence": sorted(x for req in c["requires"] for x in req.split("|") if x in conf)}
              for c in ti["chains"] if all(_has(req, conf) for req in c["requires"])]
    return chains
