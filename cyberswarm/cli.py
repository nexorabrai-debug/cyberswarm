import argparse, asyncio, json, os, shutil, socket
from .audit import Audit, verify
from .db import DB
from .log import get_logger
from .net import Net
from .orchestrator import Ctx, Orchestrator
from .report import write_reports, compare_runs, mobile_screenshot
from .scope import LABDATA, OutOfScope, resolve_scope, load_clients, is_lab
from .agents.validation import severity_table_md
def _lab_jobs(api_base):
    return [("api", os.path.join(LABDATA, "openapi.json")), ("cloud", os.path.join(LABDATA, "terraform")),
            ("mobile", os.path.join(LABDATA, "android")), ("ios", os.path.join(LABDATA, "ios")), ("code", os.path.join(LABDATA, "src"))]
def _execute(a, scope, jobs, label, meta, options=None, audit=None):
    os.makedirs(a.out, exist_ok=True)
    audit = audit or Audit(os.path.join(a.out, "audit.log"))
    net = Net(scope, audit, rate_per_sec=a.rate, timeout=a.timeout, max_requests=a.max_requests)
    ctx = Ctx(scope, get_logger(), net, audit, options or {})
    db = DB(os.path.join(a.out, "cyberswarm.db"))
    rid, fs = asyncio.run(Orchestrator(ctx, db).run(jobs, label, meta.get("client_id")))
    r = write_reports(db, rid, a.out, meta, pdf=not a.no_pdf)
    audit.log("report", run=rid, files=[os.path.basename(v) for k, v in r.items() if k != "counts" and v])
    conf = sum(f["status"] == "confirmado" for f in fs)
    print(f"Análise {rid}: {len(fs)} achados ({conf} confirmados, {len(fs)-conf} suspeitas) {r['counts']}")
    for k in ("md", "html", "pdf", "json"): print(f"  {k.upper()}: {r[k] or 'não gerado (ver README: PDF)'}")
    return rid, fs, r
def _free(port):
    s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try: s.bind(("127.0.0.1", port)); return True
    except OSError: return False
    finally: s.close()
def _start_labs(a):
    from .lab import start, start_https
    for p in (a.port, a.tls_port):
        if not _free(p): raise SystemExit(f"Porta {p} ocupada; use --port/--tls-port")
    return start(a.port), start_https(a.tls_port)
def main(argv=None):
    """Entry point (console script `cyberswarm`)."""
    p = argparse.ArgumentParser(prog="cyberswarm", description="Auditoria DEFENSIVA. Fora do laboratório, só com autorização registrada (clients.json).")
    p.add_argument("--out", default=os.path.join(os.getcwd(), "reports")); p.add_argument("--clients", default=os.path.join(os.getcwd(), "clients.json"))
    p.add_argument("--rate", type=float, default=5.0, help="requisições/segundo por host"); p.add_argument("--timeout", type=float, default=5.0)
    p.add_argument("--max-requests", type=int, default=300); p.add_argument("--no-pdf", action="store_true")
    sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("scan", help="auditar um alvo"); s.add_argument("--target", required=True); s.add_argument("--client")
    s.add_argument("--all", action="store_true"); s.add_argument("--agents", default="web,tls")
    for o in ("spec", "iac", "manifest", "plist", "code"): s.add_argument(f"--{o}")
    for name in ("demo", "demo-comercial"):
        d = sub.add_parser(name); d.add_argument("--port", type=int, default=8088); d.add_argument("--tls-port", type=int, default=8443)
        if name == "demo-comercial": d.add_argument("--screenshot", default=None)
    c = sub.add_parser("compare", help="comparar duas análises"); c.add_argument("old", type=int); c.add_argument("new", type=int); c.add_argument("--json", action="store_true")
    h = sub.add_parser("hacker", help="Hacker AI 1.0: planejar, coordenar, verificar (defensivo)")
    h.add_argument("action", nargs="?", default="run", choices=["run", "demo", "plan", "bench", "memory", "tools", "install-tools", "validate", "labs", "ui"])
    h.add_argument("--goal", default="auditar laboratório completo"); h.add_argument("--target"); h.add_argument("--client")
    h.add_argument("--approval", help="token de aprovação (approvals.json)"); h.add_argument("--approvals", default=os.path.join(os.getcwd(), "approvals.json"))
    h.add_argument("--port", type=int, default=8088); h.add_argument("--tls-port", type=int, default=8443)
    h.add_argument("--tool", action="append", default=[], help="forçar ferramenta, ex.: codesec=bandit")
    h.add_argument("--lab", default="all", help="1.1 validate: juice-shop|webgoat|vampi|dvga|insecurebankv2|all")
    h.add_argument("--mode", default="both", choices=["1.0", "1.1", "both"]); h.add_argument("--no-nuclei", action="store_true"); h.add_argument("--no-mobsf", action="store_true")
    h.add_argument("--pdf-path"); h.add_argument("--ui-port", type=int, default=8765)
    k = sub.add_parser("control", help="CyberSwarm Control 1.0 (PWA + API autenticada)")
    k.add_argument("action", choices=["serve", "init", "adduser"])
    k.add_argument("--data", default=os.environ.get("CONTROL_DATA") or os.environ.get("CYBERSWARM_DATA") or os.path.join(os.getcwd(), "control-data"))
    k.add_argument("--host", default=os.environ.get("CONTROL_HOST") or os.environ.get("HOST") or "127.0.0.1")
    k.add_argument("--port", type=int, default=int(os.environ.get("PORT") or os.environ.get("CONTROL_PORT") or "8770"))
    k.add_argument("--allow-lan", action="store_true")
    k.add_argument("--secure-cookie", action="store_true", help="atrás de túnel HTTPS"); k.add_argument("--user"); k.add_argument("--role", default="viewer", choices=["owner", "viewer"])
    k.add_argument("--clients-only", help="viewer restrito a estes clientes (vírgula)")
    k.add_argument("--tls", action="store_true", help="HTTPS com certificado autoassinado (ou --cert/--key)")
    k.add_argument("--cert"); k.add_argument("--key"); k.add_argument("--no-workers", action="store_true", help="HTTP só; use `cyberswarm worker` à parte")
    w = sub.add_parser("worker", help="Daemon de fila do Control (independente do navegador)")
    w.add_argument("--data", default=os.environ.get("CONTROL_DATA") or os.environ.get("CYBERSWARM_DATA") or os.path.join(os.getcwd(), "control-data")); w.add_argument("--poll", type=float, default=1.0); w.add_argument("--once", action="store_true")
    sub.add_parser("severity-table"); sub.add_parser("audit-verify"); sub.add_parser("clients-check")
    a = p.parse_args(argv)
    if a.cmd == "severity-table": print(severity_table_md()); return 0
    if a.cmd == "worker":
        from .control.daemon import main as worker_main
        return worker_main(["--data", a.data, "--poll", str(a.poll)] + (["--once"] if a.once else []))
    if a.cmd == "control":
        from .control.cli import control_main
        return control_main(a)
    if a.cmd == "hacker":
        if a.action in ("validate", "labs", "ui"):
            from .extval.cli import extval_main
            return extval_main(a)
        from .hacker.cli import hacker_main
        return hacker_main(a)
    if a.cmd == "audit-verify":
        ok, line = verify(os.path.join(a.out, "audit.log")); print("Trilha de auditoria íntegra" if ok else f"ADULTERADA na linha {line}"); return 0 if ok else 1
    if a.cmd == "clients-check":
        cl = load_clients(a.clients); print(f"{len(cl)} cliente(s) válidos no formato: {', '.join(cl) or '-'}"); return 0
    if a.cmd == "compare":
        db = DB(os.path.join(a.out, "cyberswarm.db")); r = compare_runs(db, a.old, a.new)
        Audit(os.path.join(a.out, "audit.log")).log("compare", old=a.old, new=a.new, **{k: len(v) for k, v in r.items()})
        if a.json: print(json.dumps({k: [f["fingerprint"] for f in v] for k, v in r.items()})); return 0
        for k, v in r.items():
            print(f"{k.upper()}: {len(v)}")
            for f in v: print(f"  [{f['severity']}] {f['fingerprint']} {f['agent']}: {f['title']}")
        return 0
    if a.cmd == "scan":
        audit = Audit(os.path.join(a.out, "audit.log"))
        try:
            scope = resolve_scope(a.target, a.clients, a.client)
        except (OutOfScope, ValueError) as e:
            audit.log("scope_denied", target=a.target, client=a.client, reason=str(e))
            print(f"BLOQUEADO: {e}"); return 2
        audit.log("scope_ok", target=a.target, client=a.client)
        names = ["web", "tls", "api", "cloud", "mobile", "ios", "code"] if a.all else a.agents.split(",")
        lab = is_lab(a.target) and not a.client; files = dict(_lab_jobs(None)) if lab else {}
        opt = {"spec": "api", "iac": "cloud", "manifest": "mobile", "plist": "ios", "code": "code"}
        for o, ag in opt.items():
            if getattr(a, o): files[ag] = getattr(a, o)
        jobs = []
        for n in names:
            if n in ("web", "tls"):
                if n == "tls" and not a.target.startswith("https://"): continue
                jobs.append((n, a.target))
            elif n in files: jobs.append((n, files[n]))
        meta = {"client_id": a.client, "client_name": (scope.client or {}).get("name", "Laboratório CyberSwarm"),
                "authorization_ref": (scope.client or {}).get("authorization_ref", "LAB (ambiente próprio)")}
        _execute(a, scope, jobs, a.target, meta, audit=audit); return 0
    if a.cmd in ("demo", "demo-comercial"):
        from .scope import Scope
        http_srv, https_srv = _start_labs(a)
        http_t, https_t = f"http://127.0.0.1:{a.port}", f"https://127.0.0.1:{a.tls_port}"
        try:
            jobs = [("web", http_t), ("web", https_t), ("tls", https_t)]
            if a.cmd == "demo": jobs += _lab_jobs(http_t)
            else: jobs += [("api", os.path.join(LABDATA, "openapi.json"))]
            meta = {"client_name": "Laboratório CyberSwarm (demonstração)", "authorization_ref": "LAB-DEMO (ambiente próprio, 127.0.0.1)"}
            rid, fs, r = _execute(a, Scope.lab(), jobs, "demo" if a.cmd == "demo" else "demo-comercial", meta, {"api_base": http_t})
            if a.cmd == "demo-comercial":
                png, sw = mobile_screenshot(r["html"], a.screenshot or r["html"][:-5] + "-mobile.png")
                print(f"  CELULAR (390px): {png or 'não gerado (sem Playwright/Chrome)'}" + (f" | largura da página {sw}px (sem rolagem lateral: {sw <= 390})" if sw else ""))
            return 0
        finally:
            for srv in (http_srv, https_srv): srv.shutdown(); srv.server_close()
