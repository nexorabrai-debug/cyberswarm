"""`cyberswarm hacker ...` commands."""
import json, os, subprocess, sys
from ..scope import OutOfScope, resolve_scope, Scope
from ..tools import which
from .engine import HackerAI, lab_targets
from .planner import plan
from .selector import CANDIDATES, VERIFIERS, select
TOOLS = ["bandit", "semgrep", "sslyze", "checkov"]
def _labs(a):
    from ..cli import _start_labs
    return _start_labs(a)
def _print(s):
    m = s["metrics"]; v = s["verification"]
    print(f"Hacker AI run {s['hacker_run']} (análise {s['core_run']}): {s['findings']} achados, {s['confirmed']} confirmados | {s['elapsed_s']}s | {s['messages']} mensagens no barramento")
    print(f"  Plano: {len(s['plan']['tasks'])} tarefas em {len(s['plan']['levels'])} níveis; módulos: {', '.join(s['modules'])}")
    print(f"  Ferramentas: " + ", ".join(f"{k}={s['tool_used'].get(k, t)}" for k, t in s["tools"].items()))
    print(f"  Verificação: {v['reproduced']}/{v['checked']} reproduzidos, {v['downgraded']} rebaixados, {v['corroborated']} corroborados ({', '.join(f'{k}={t}' for k, t in v['tools'].items() if t != 'builtin-rerun')})")
    print(f"  Hipóteses: " + ", ".join(f"#{h['id']} {h['status']}" for h in s["hypotheses"]) + f" | cadeias de ataque: {len(s['chains'])}")
    print(f"  Memória: {s['new']} novos, {s['recurring']} recorrentes")
    if s["denied"]: print(f"  NEGADO pelo portão de aprovação: {', '.join(s['denied'])}")
    if m: print(f"  Métricas vs gabarito: precisão {m['precision']} revocação {m['recall']} F1 {m['f1']} (VP {m['tp']} FP {m['fp']} FN {m['fn']})")
    for k in ("md", "html", "pdf"): print(f"  {k.upper()}: {s['reports'][k]}")
def hacker_main(a):
    force = dict(x.split("=", 1) for x in a.tool)
    if a.action == "tools":
        for t in TOOLS + ["nmap", "gitleaks", "trufflehog", "nuclei", "zap.sh", "garak", "ollama"]: print(f"{t:12s} {which(t) or 'não instalado'}")
        for m in CANDIDATES: print(f"seleção {m}: {select(m, {'codesec': 'code', 'network': 'tcp'}[m])['tool']}")
        return 0
    if a.action == "install-tools":
        hk = HackerAI(a.out, a.approvals)
        if not hk.gate.check("system_change", "local:~/.cyberswarm-tools", a.approval):
            print("NEGADO: instalar ferramentas altera o sistema; requer token 'system_change' em approvals.json (--approval)"); return 3
        venv = os.path.expanduser("~/.cyberswarm-tools")
        subprocess.run([sys.executable, "-m", "venv", venv], check=True); r = subprocess.run([os.path.join(venv, "bin", "pip"), "install", "-q"] + TOOLS)
        hk.audit.log("system_change", what="pip install " + " ".join(TOOLS), rc=r.returncode); return r.returncode
    if a.action == "memory":
        from .memory import Memory
        m = Memory(os.path.join(a.out, "hacker_memory.db"))
        print(json.dumps({"runs": m.runs(), "tools": m.all_tools(), "hypotheses": m.hypotheses()}, indent=1, ensure_ascii=False, default=str)); return 0
    client_mode = bool(a.target)
    if a.action == "plan":
        t = lab_targets(f"http://127.0.0.1:{a.port}", f"https://127.0.0.1:{a.tls_port}") if not client_mode else {"url": a.target, "https": a.target if a.target.startswith("https") else None}
        print(json.dumps(plan(a.goal, t, lab=not client_mode), indent=1, ensure_ascii=False)); return 0
    hk = HackerAI(a.out, a.approvals, rate=5.0 if client_mode else 20.0, timeout=a.timeout, max_requests=a.max_requests if client_mode else 1000)
    if client_mode:
        try: scope = resolve_scope(a.target, a.clients, a.client)
        except (OutOfScope, ValueError) as e:
            hk.audit.log("scope_denied", target=a.target, client=a.client, reason=str(e)); print(f"BLOQUEADO: {e}"); return 2
        t = {"url": a.target if a.target.startswith("http://") else None, "https": a.target if a.target.startswith("https://") else None}
        c = scope.client or {}
        s = hk.run(a.goal, t, scope, a.client, a.approval, pdf=not a.no_pdf, force_tools=force,
                   meta={"client_name": c.get("name", a.client), "authorization_ref": c.get("authorization_ref", "-")})
        _print(s); return 0 if not s["denied"] else 3
    http_srv, https_srv = _labs(a)
    try:
        goal = a.goal if a.action == "run" else "auditar laboratório completo"
        s = hk.run(goal, lab_targets(f"http://127.0.0.1:{a.port}", f"https://127.0.0.1:{a.tls_port}"), pdf=not a.no_pdf, force_tools=force)
        _print(s)
        if a.action == "bench":
            rows = []
            for tool in ("builtin", "bandit", "semgrep"):
                r = hk.run("auditar código", lab_targets(f"http://127.0.0.1:{a.port}", f"https://127.0.0.1:{a.tls_port}"), pdf=False, force_tools={"codesec": tool})
                cm = r["metrics"]["per_module"].get("codesec", {}); p = next((x for x in r["perf"] if x["agent"] == "codesec"), {})
                rows.append({"tool": r["tool_used"].get("codesec"), **cm, "secs": p.get("secs")})
            print(json.dumps({"codesec_bench": rows}, ensure_ascii=False))
        return 0
    finally:
        for srv in (http_srv, https_srv): srv.shutdown(); srv.server_close()
