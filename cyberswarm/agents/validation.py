"""Validation: fingerprint, dedupe, status (confirmado/suspeita), severity validation against the catalog."""
import os
from urllib.parse import urlparse, urlunparse
from ..checks import C
from .common import sha, display_path
SEV = ["info", "low", "medium", "high", "critical"]
SUSPECT_MAX = "medium"
def normalize_target(t):
    if "://" in t:
        u = urlparse(t); host = (u.hostname or "").lower(); port = u.port or {"http": 80, "https": 443}.get(u.scheme)
        return urlunparse((u.scheme.lower(), f"{host}:{port}", u.path.rstrip("/") or "/", "", u.query, ""))
    return display_path(t)
def fingerprint(f):
    return sha(f"{f['agent']}|{f['check_id']}|{normalize_target(f['target'])}|{sha(f.get('evidence', ''))[:16]}")[:16]
def proof_status(p):
    """confirmado only with reproducible evidence; file proofs are re-verified against the file on disk."""
    if not p: return "suspeita"
    if p.get("type") == "http" and p.get("request") and p.get("response") and p.get("curl"): return "confirmado"
    if p.get("type") in ("tls", "tcp") and p.get("command") and p.get("observed"): return "confirmado"
    if p.get("type") == "file" and p.get("line", 0) > 0 and os.path.exists(p.get("abs", "")):
        lines = open(p["abs"], errors="ignore").read().splitlines()
        if p["line"] <= len(lines) and sha(lines[p["line"] - 1]) == p.get("line_sha"): return "confirmado"
    return "suspeita"
def validate_severity(f):
    """Returns final severity. Rule 1: catalog severity is authoritative. Rule 2: 'suspeita' is capped at medium."""
    sev = C[f["check_id"]]["severity"]
    if f["status"] == "suspeita" and SEV.index(sev) > SEV.index(SUSPECT_MAX): sev = SUSPECT_MAX
    return sev
PRIORITY = {"critical": "P1", "high": "P2", "medium": "P3", "low": "P4", "info": "P5"}
def validate(findings):
    seen, out = set(), []
    for f in findings:
        fp = fingerprint(f)
        if fp in seen: continue
        seen.add(fp); f["fingerprint"] = fp
        f["status"] = proof_status(f.get("proof"))
        f["severity"] = validate_severity(f)
        f["priority"] = PRIORITY[f["severity"]]
        out.append(f)
    return sorted(out, key=lambda x: (-SEV.index(x["severity"]), x["status"] != "confirmado", x["agent"], x["title"]))
def severity_table_md():
    rows = ["| check_id | gravidade | título |", "|---|---|---|"]
    rows += [f"| `{k}` | {v['severity']} | {v['title']} |" for k, v in sorted(C.items())]
    return "\n".join(rows)
