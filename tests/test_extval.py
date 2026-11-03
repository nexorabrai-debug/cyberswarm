"""HACKER AI 1.1 — validação externa: probes, wrappers (nuclei/MobSF) com trava de escopo, APK, métricas, recuperação, paralelismo, UI."""
import asyncio, json, os, socket, stat, sys, threading, time, urllib.request, urllib.error, pytest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from conftest import free_port, T
from cyberswarm.scope import Scope, OutOfScope
from cyberswarm.audit import Audit
from cyberswarm.net import Net
from cyberswarm.log import get_logger
from cyberswarm.db import DB
from cyberswarm.orchestrator import Ctx, Orchestrator
from cyberswarm.agents.validation import validate
from cyberswarm.extval import probes, tools_ext, apk as apkmod  # noqa: F401
from cyberswarm.extval.metrics import evaluate, load_gt, load_map, D
from cyberswarm.extval.labs import LABS, LABS_DIR
VULN = {"/robots.txt": (200, "text/plain", "User-agent: *\nDisallow: /files\n"),
        "/files": (200, "text/html", "<html><title>listing directory /files</title><a href='a.pdf'>a.pdf</a></html>"),
        "/metrics": (200, "text/plain", "# HELP up ok\n# TYPE up gauge\nup 1\n"),
        "/openapi.json": (200, "application/json", json.dumps({"openapi": "3.0.0", "paths": {"/users/debug": {"get": {}}, "/users/{id}": {"get": {}}}})),
        "/users/debug": (200, "application/json", '[{"username":"a","password":"Secret123"}]'),
        "/graphiql": (200, "text/html", "<html>GraphiQL</html>")}
def gql(q):
    if "__schema" in q: return '{"data":{"__schema":{"queryType":{"name":"Query"},"types":[{"name":"Query"}]}}}'
    if "__typename" in q: return '{"data":{"__typename":"Query"}}'
    return '{"errors":[{"message":"Cannot query field \\"cyberswarmx\\". Did you mean \\"cyber\\"?"}]}'
def server(routes, graphql=False):
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a): pass
        def do_GET(self):
            p, _, q = self.path.partition("?")
            if graphql and p == "/graphql":
                from urllib.parse import parse_qs
                b = gql(parse_qs(q).get("query", [""])[0]); c, t = 200, "application/json"
            elif p in routes: c, t, b = routes[p]
            else: c, t, b = 404, "text/html", "<html>not found</html>"
            self.send_response(c); self.send_header("Content-Type", t); self.end_headers(); self.wfile.write(b.encode())
        do_HEAD = do_GET
        def do_OPTIONS(self): self.send_response(200); self.end_headers()
    port = free_port(); s = ThreadingHTTPServer(("127.0.0.1", port), H); threading.Thread(target=s.serve_forever, daemon=True).start()
    return s, f"http://127.0.0.1:{port}"
def mkctx(tmp_path, opts=None, scope=None):
    sc = scope or Scope(paths=[str(tmp_path)]); au = Audit(str(tmp_path / "audit.log"))
    return Ctx(sc, get_logger("t"), Net(sc, au, rate_per_sec=500), au, opts or {})
def run(name, target, ctx):
    from cyberswarm.registry import REGISTRY
    return asyncio.run(REGISTRY[name](ctx).run(target))
# ---------- ground truth (oficial) ----------
@pytest.mark.parametrize("lab", ["juice-shop", "webgoat", "vampi", "dvga", "insecurebankv2", "crapi"])
def test_ground_truth_official_sources(lab):
    g = load_gt(lab); assert g["source"].startswith("https://github.com/") and len(g["items"]) >= 9
    ids = {i["id"] for i in g["items"]}; assert len(ids) == len(g["items"])
    for r in load_map(lab): assert r["item"] in ids, r
def test_metrics_definitions():
    f = lambda cid, st, **k: {"agent": "x", "check_id": cid, "status": st, "fingerprint": cid + st, "target": "t", "title": "", "evidence": "", **k}
    m = evaluate("vampi", [f("api.ratelimit.live", "confirmado"), f("web.header.csp", "confirmado"), f("ext.nuclei.info", "suspeita", tool="nuclei", template="x")])
    assert (m["detectados"], m["achados_mapeados"], m["confirmados_nao_listados"], m["nao_reproduzidos"]) == (1, 1, 1, 1)
    assert m["revocacao"] == round(1 / 9, 4) and m["precisao_estrita"] == round(1 / 3, 4) and m["nao_detectados"] == 8
# ---------- probes ----------
def test_probes_detect_and_negatives(tmp_path):
    s, u = server(VULN, graphql=True); c = mkctx(tmp_path)
    try:
        d = T(run("discovery", u, c)); g = T(run("graphql", u, c)); a = run("apidata", u, c)
    finally: s.shutdown()
    assert {"web.dirlisting", "web.metrics_exposed", "web.api_docs_exposed"} <= set(d)
    assert {"gql.introspection", "gql.suggestions", "gql.graphiql"} <= set(g)
    assert T(a) == ["api.excessive_data"] and "Secret123" not in json.dumps(a)  # masked
    s, u = server({"/robots.txt": (200, "text/plain", "Disallow: /files\n"), "/files": (200, "text/html", "<html>ok</html>")}); c = mkctx(tmp_path)
    try: assert run("discovery", u, c) == [] and run("graphql", u, c) == [] and run("apidata", u, c) == []
    finally: s.shutdown()
def test_probes_scope_locked(tmp_path):
    with pytest.raises(OutOfScope): run("discovery", "http://example.com", mkctx(tmp_path))
# ---------- nuclei wrapper ----------
FAKE = r'''#!{py}
import json, sys, time, os
a = sys.argv; u = a[a.index("-u") + 1]; o = a[a.index("-o") + 1]; port = u.split(":")[2].split("/")[0]
hits = [{{"template-id": "prometheus-metrics", "info": {{"severity": "medium"}}, "matched-at": u + "/metrics"}},
        {{"template-id": "novnc-login-panel", "info": {{"severity": "info"}}, "matched-at": "http://127.0.0.1:6080/vnc.html"}},
        {{"template-id": "fake-hit", "info": {{"severity": "high"}}, "matched-at": u + "/naoexiste"}}]
with open(o, "w") as f:
    for h in hits: f.write(json.dumps(h) + "\n"); f.flush()
    if os.environ.get("FAKE_SLEEP"): time.sleep(float(os.environ["FAKE_SLEEP"]))
    if os.environ.get("FAKE_CRASH"): os.kill(os.getpid(), 9)
'''
@pytest.fixture
def fake_nuclei(tmp_path, monkeypatch):
    b = tmp_path / "bin"; b.mkdir(); p = b / "nuclei"; p.write_text(FAKE.format(py=sys.executable)); p.chmod(0o755)
    monkeypatch.setenv("CYBERSWARM_TOOLBIN", str(b)); return p
def test_nuclei_hits_need_reproduction_and_port_lock(tmp_path, fake_nuclei):
    s, u = server(VULN); c = mkctx(tmp_path)
    try: fs = validate(run("nuclei", u, c))
    finally: s.shutdown()
    by = {f["template"]: f for f in fs}
    assert "novnc-login-panel" not in by                      # other port: discarded
    assert by["prometheus-metrics"]["status"] == "confirmado"  # reproduced by our Net
    assert by["fake-hit"]["status"] == "suspeita" and by["fake-hit"]["severity"] == "medium"  # not reproduced: capped
    assert c.options["tool_stats"][f"nuclei:{u}"]["discarded_out_of_port"] == 1
    assert "tool_hit_discarded" in open(tmp_path / "audit.log").read()
def test_nuclei_refuses_non_lab_without_client(tmp_path, fake_nuclei):
    sc = Scope(hosts=["cliente.example"]); c = mkctx(tmp_path, scope=sc)
    with pytest.raises(PermissionError): run("nuclei", "http://cliente.example", c)
def test_mobsf_locked_to_localhost(tmp_path, monkeypatch):
    monkeypatch.setenv("MOBSF_URL", "http://10.0.0.5:8000")
    with pytest.raises(PermissionError): tools_ext._mobsf_post("/api/v1/scan", {"hash": "x"}, "k")
# ---------- recuperação e paralelismo ----------
def orch_run(c, jobs, tmp_path, **k):
    tasks = []; o = Orchestrator(c, DB(str(tmp_path / "c.db")), on_task=lambda n, t, s, q, secs, a: tasks.append((n, s, q)), **k)
    _, fs = asyncio.run(o.run(jobs)); return fs, tasks
def test_tool_killed_mid_run_keeps_partial(tmp_path, fake_nuclei, monkeypatch):
    monkeypatch.setenv("FAKE_CRASH", "1"); s, u = server(VULN)
    try: fs, tasks = orch_run(mkctx(tmp_path), [("nuclei", u), ("discovery", u)], tmp_path)
    finally: s.shutdown()
    st = dict((n, s_) for n, s_, _ in tasks)
    assert st == {"nuclei": "partial", "discovery": "done"} and any(f.get("template") == "prometheus-metrics" for f in fs)
def test_tool_timeout_killed_partial(tmp_path, fake_nuclei, monkeypatch):
    monkeypatch.setenv("FAKE_SLEEP", "30"); s, u = server(VULN); t0 = time.monotonic()
    try: fs, tasks = orch_run(mkctx(tmp_path, {"nuclei_timeout": 2}), [("nuclei", u)], tmp_path)
    finally: s.shutdown()
    assert time.monotonic() - t0 < 15 and tasks[0][1] == "partial" and len(fs) == 2
def test_lab_down_isolated_and_retried(tmp_path):
    s, u = server(VULN); dead = f"http://127.0.0.1:{free_port()}"
    try: fs, tasks = orch_run(mkctx(tmp_path), [("discovery", dead), ("discovery", u), ("graphql", dead)], tmp_path, retries=1, backoff=0.01)
    finally: s.shutdown()
    assert sorted(s_ for _, s_, _ in tasks) == ["done", "error", "error"] and "web.metrics_exposed" in T(fs)
    assert open(tmp_path / "audit.log").read().count("task_retry") == 2
def test_concurrency_stress_deterministic(tmp_path):
    s, u = server(VULN, graphql=True)
    try:
        jobs = [(a, u) for a in ("discovery", "graphql", "apidata", "web")] * 12
        par, tp = orch_run(mkctx(tmp_path, scope=Scope(paths=[str(tmp_path)])), jobs, tmp_path, workers=16)
        ser, ts = orch_run(mkctx(tmp_path), jobs[:4], tmp_path, workers=1)
    finally: s.shutdown()
    assert len(tp) == 48 and all(x[1] == "done" for x in tp)
    assert sorted(f["fingerprint"] for f in par) == sorted(f["fingerprint"] for f in ser)  # dedupe: same result as serial
# ---------- APK (real, se disponível) ----------
APK = LABS["insecurebankv2"]["apk"]
@pytest.mark.skipif(not os.path.exists(APK) or not apkmod.tools_python(), reason="APK/androguard ausentes (scripts/fetch_labs.sh)")
def test_apk_real_static_analysis_and_tamper(tmp_path):
    c = mkctx(tmp_path, {"artifacts_dir": str(tmp_path / "art")}, scope=Scope(paths=[LABS_DIR, str(tmp_path)]))
    fs = validate(run("apk", APK, c)); ids = set(T(fs))
    assert {"apk.debuggable", "apk.allowbackup", "apk.exported.provider", "apk.exported.receiver", "apk.webview_js", "apk.hardcoded_key"} <= ids
    assert all(f["status"] == "confirmado" for f in fs) and "This is the super secret key" not in json.dumps(fs)
    m = next(f for f in fs if f["check_id"] == "apk.debuggable"); p = m["proof"]["abs"]
    open(p, "w").write(open(p).read().replace('debuggable="true"', 'debuggable="false"'))
    assert validate([dict(m)])[0]["status"] == "suspeita"   # tampered artifact no longer proves it
def test_mobsf_corroboration():
    ours = {"agent": "apk", "check_id": "apk.debuggable", "status": "confirmado", "fingerprint": "f1", "proof": {"type": "file"}}
    a = {"agent": "mobsf", "tool": "mobsf", "category": "apk.debuggable", "status": "suspeita", "proof": {}}
    b = {"agent": "mobsf", "tool": "mobsf", "category": None, "status": "suspeita", "proof": {}}
    assert tools_ext.corroborate([ours, a, b]) == 1 and a["status"] == "confirmado" and a["corroborated_by"] == "f1" and b["status"] == "suspeita"
# ---------- UI ----------
def req(url, data=None, cookie=None):
    r = urllib.request.Request(url, data=data.encode() if data else None, headers={"Cookie": cookie} if cookie else {})
    op = urllib.request.build_opener(type("N", (urllib.request.HTTPRedirectHandler,), {"redirect_request": lambda *a, **k: None}))
    try:
        with op.open(r, timeout=5) as x: return x.status, dict(x.headers), x.read().decode()
    except urllib.error.HTTPError as e: return e.code, dict(e.headers), e.read().decode()
def test_ui_auth_csrf_and_mobile(tmp_path):
    from cyberswarm.extval.ui import serve
    port = free_port(); srv = serve(str(tmp_path), port=port, token="tok-test-123", block=False); b = f"http://127.0.0.1:{port}"
    try:
        assert srv.server_address[0] == "127.0.0.1"
        assert req(b + "/")[0] == 401 and req(b + "/api/runs")[0] == 401
        assert req(b + "/login", "token=errado")[0] == 401
        st, h, _ = req(b + "/login", "token=tok-test-123"); assert st == 303 and "HttpOnly" in h["Set-Cookie"]
        ck = "cs_token=tok-test-123"; st, h, body = req(b + "/", cookie=ck)
        assert st == 200 and "width=device-width" in body and "juice-shop" in body and h["X-Frame-Options"] == "DENY"
        assert req(b + "/scan", "lab=juice-shop", cookie=ck)[0] == 403            # sem CSRF
        from cyberswarm.extval.ui import State
        csrf = State(str(tmp_path), "tok-test-123").csrf
        assert req(b + "/scan", f"lab=http://evil.com&csrf={csrf}", cookie=ck)[0] == 400  # só labs registrados
        assert req(b + "/report.pdf/../../etc/passwd", cookie=ck)[0] == 404
        assert oct(os.stat(tmp_path / "ui_token").st_mode)[-3:] == "600"
    finally: srv.shutdown()
def test_cli_labs_lists_crapi_reason(capsys):
    from cyberswarm.cli import main
    assert main(["hacker", "labs"]) == 0; out = capsys.readouterr().out
    assert "crapi" in out and "Docker" in out
