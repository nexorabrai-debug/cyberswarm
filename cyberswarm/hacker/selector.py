"""Tool selector: per module, picks the best AVAILABLE tool by (prior accuracy estimate, past performance in operational
memory, target type). Deterministic. Always ends in a built-in fallback, so a missing tool never breaks a run.
Priors are rough, documented in docs/HACKER_AI_PLANO.md and marked [não verificado] - memory corrects them over time."""
from ..tools import which
CANDIDATES = {  # module -> [(tool, executable or None for builtin, prior 0..1, target types)]
    "codesec": [("semgrep", "semgrep", 0.80, {"code"}), ("bandit", "bandit", 0.75, {"code"}), ("builtin", None, 0.60, {"code"})],
    "network": [("nmap", "nmap", 0.85, {"tcp"}), ("builtin", None, 0.70, {"tcp"})],
}
VERIFIERS = {  # independent second opinion used by verification step
    "tls": [("sslyze", "sslyze"), ("builtin-rerun", None)], "cloud": [("checkov", "checkov"), ("builtin-rerun", None)],
    "codesec": [("bandit", "bandit"), ("semgrep", "semgrep"), ("builtin-ast", None)]}
def available(exe): return exe is None or which(exe) is not None
def score(tool, module, prior, memory):
    s = memory.tool_stats(tool, module) if memory else None
    if not s or not s["runs"]: return prior, "prior"
    ok_rate = s["ok"] / s["runs"]; q = (s["tp"] / (s["tp"] + s["fp"])) if (s["tp"] + s["fp"]) else prior
    avg = s["secs"] / s["runs"]; speed = 1.0 if avg < 5 else 0.8 if avg < 30 else 0.6
    return round(0.4 * prior + 0.3 * ok_rate * q + 0.3 * q * speed, 4), f"memória: {s['runs']} execuções, ok {s['ok']}, tp {s['tp']}, fp {s['fp']}, média {avg:.1f}s"
def select(module, target_type, memory=None):
    """Returns dict(tool, reason, ranking[]); tool='builtin' when the module has no external candidates."""
    cands = CANDIDATES.get(module)
    if not cands: return {"module": module, "tool": "builtin", "reason": "módulo nativo do CyberSwarm", "ranking": []}
    ranking = []
    for tool, exe, prior, types in cands:
        if target_type not in types: continue
        ok = available(exe); sc, why = score(tool, module, prior, memory)
        ranking.append({"tool": tool, "available": ok, "score": sc if ok else 0.0, "why": why if ok else "não instalado"})
    ranking.sort(key=lambda r: -r["score"])
    best = next(r for r in ranking if r["available"])
    return {"module": module, "tool": best["tool"], "reason": best["why"], "ranking": ranking}
def select_verifier(module, primary=None):
    for tool, exe in VERIFIERS.get(module, [("builtin-rerun", None)]):
        if tool != primary and available(exe): return tool
    return "builtin-rerun"
