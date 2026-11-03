"""CyberSwarm Control 1.0: autenticação em toda rota, limite de força bruta, sem endpoint de comando, aprovações, separação de clientes, PWA válida."""
import json, os, re, time, urllib.request, urllib.error, http.cookiejar, pytest
from conftest import free_port
from cyberswarm.control import server as S
from cyberswarm.control.store import Store, check_pw, hash_pw
PW = "Senha-Teste-2026"
class C:
    def __init__(self, base):
        self.b = base; self.cj = http.cookiejar.CookieJar(); self.op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(self.cj)); self.csrf = None
    def __call__(self, m, p, body=None, csrf=True, headers=None):
        h = {"Content-Type": "application/json", **(headers or {})}
        if csrf and self.csrf: h["X-CSRF-Token"] = self.csrf
        r = urllib.request.Request(self.b + p, data=json.dumps(body).encode() if body is not None else None, headers=h, method=m)
        try:
            with self.op.open(r, timeout=30) as x: raw = x.read(); return x.status, (json.loads(raw) if "json" in x.headers.get("Content-Type", "") else raw), dict(x.headers)
        except urllib.error.HTTPError as e: return e.code, json.loads(e.read() or b"{}"), dict(e.headers)
    def login(self, u="dono", pw=PW):
        st, d, h = self("POST", "/api/login", {"username": u, "password": pw}); self.csrf = d.get("csrf") if st == 200 else None; return st, d, h
@pytest.fixture
def srv(tmp_path):
    st = Store(str(tmp_path / "control.db")); st.add_user("dono", PW, "owner"); st.add_user("leitor", PW, "viewer", ["cli-a"]); st.add_user("geral", PW, "viewer")
    del st
    port = free_port(); s = S.serve(str(tmp_path), port=port, autostart=False, block=False)
    yield s, f"http://127.0.0.1:{port}", tmp_path
    s.shutdown()
CLI = lambda cid, host: {"id": cid, "name": cid.upper(), "authorization_ref": "TERMO-T-1", "authorized_by": "Fulano", "valid_from": "2026-01-01", "valid_until": "2099-12-31", "hosts": [host]}
def test_scrypt_hash():
    h = hash_pw(PW); assert h.startswith("scrypt$16384$8$1$") and PW not in h and check_pw(PW, h) and not check_pw("errada-xxxxx", h)
    with pytest.raises(ValueError): hash_pw("curta")
def test_every_api_route_requires_auth(srv):
    _, b, _ = srv; c = C(b); sample = {r"(\d+)": "1", r"([\w.-]+)": "x.pdf", r"([a-z0-9-]+)": "cli-a"}
    checked = 0
    for meth, rx, fn, role in S.ROUTES:
        path = rx.pattern[1:-1]
        for k, v in sample.items(): path = path.replace(k, v)
        st, d, _ = c(meth, path, {} if meth != "GET" else None)
        if role == "public": assert path in ("/api/login", "/api/ping"); continue
        assert st == 401, (meth, path, st); checked += 1
    assert checked == len(S.ROUTES) - 2 >= 24
def test_session_cookie_flags_and_logout(srv):
    _, b, _ = srv; c = C(b); st, d, h = c.login()
    assert st == 200 and "HttpOnly" in h["Set-Cookie"] and "SameSite=Strict" in h["Set-Cookie"] and "csrf" in d and PW not in json.dumps(d)
    assert c("GET", "/api/me")[0] == 200
    assert c("POST", "/api/logout")[0] == 200 and c("GET", "/api/me")[0] == 401
def test_session_token_stored_hashed(srv):
    s, b, tmp = srv; c = C(b); c.login(); tok = next(k.value for k in c.cj)
    import sqlite3; rows = sqlite3.connect(tmp / "control.db").execute("SELECT th FROM sessions").fetchall()
    assert rows and all(tok != r[0] for r in rows)
    assert oct(os.stat(tmp / "control.db").st_mode)[-3:] == "600"
def test_bruteforce_limit(srv):
    s, b, tmp = srv; c = C(b)
    for _ in range(5): assert c.login(pw="errada-123456")[0] == 401
    assert c.login()[0] == 429                       # bloqueado mesmo com a senha certa
    assert c.login("geral")[0] == 429                # mesmo IP: bloqueado
    log = open(tmp / "control_audit.log").read(); assert log.count("login_failed") == 5 and "login_locked" in log and PW not in log
def test_unknown_user_no_enumeration(srv):
    _, b, _ = srv; st1, d1, _ = C(b).login("naoexiste"); st2, d2, _ = C(b).login("dono", "errada-123456")
    assert st1 == st2 == 401 and d1 == d2
def test_csrf_origin_and_content_type(srv):
    _, b, _ = srv; c = C(b); c.login()
    assert c("POST", "/api/clients", CLI("cli-a", "a.test"), csrf=False)[0] == 403
    assert c("POST", "/api/clients", CLI("cli-a", "a.test"), headers={"Origin": "http://evil.test"})[0] == 403
    r = urllib.request.Request(b + "/api/clients", data=b"id=x", headers={"X-CSRF-Token": c.csrf, "Content-Type": "application/x-www-form-urlencoded"}, method="POST")
    with pytest.raises(urllib.error.HTTPError) as e: c.op.open(r)
    assert e.value.code == 415
def test_no_command_execution_endpoint(srv):
    _, b, _ = srv; c = C(b); c.login()
    for p in ("/api/exec", "/api/shell", "/api/cmd", "/api/run", "/api/command", "/api/terminal"):
        assert c("POST", p, {"cmd": "id"})[0] == 404
    assert not [r for r in S.ROUTES if re.search(r"exec|shell|cmd|command|terminal|eval", r[1].pattern)]
    src = "".join(open(os.path.join(os.path.dirname(S.__file__), f)).read() for f in os.listdir(os.path.dirname(S.__file__)) if f.endswith(".py"))
    assert not re.search(r"\bsubprocess\b|os\.system|os\.popen|\beval\(|\bexec\(|shell=True", src)
def test_viewer_is_read_only(srv):
    _, b, _ = srv; o = C(b); o.login(); assert o("POST", "/api/clients", CLI("cli-a", "a.test"))[0] == 200
    v = C(b); v.login("geral")
    assert v("GET", "/api/clients")[0] == 200
    for m, p, body in (("POST", "/api/clients", CLI("cli-z", "z.test")), ("POST", "/api/jobs", {"client_id": "_lab"}), ("POST", "/api/approvals/1", {"decision": "approve", "reason": "x"}),
                       ("POST", "/api/finance", {"date": "2026-11-01", "kind": "receita", "amount": 1, "description": "x"}), ("POST", "/api/tools", {"disabled": []}),
                       ("DELETE", "/api/clients/cli-a", None), ("POST", "/api/users", {"username": "x", "password": PW})):
        assert v(m, p, body)[0] == 403, p
def test_client_scope_crud_and_validation(srv):
    _, b, tmp = srv; c = C(b); c.login()
    assert c("POST", "/api/clients", {**CLI("cli-a", "a.test"), "password": "x"})[0] == 400        # credenciais recusadas
    assert c("POST", "/api/clients", {**CLI("cli-a", "a.test"), "authorization_ref": ""})[0] == 400  # termo obrigatório
    assert c("POST", "/api/clients", CLI("cli-a", "*.a.test"))[0] == 400                            # sem curingas
    assert c("POST", "/api/clients", CLI("../x", "a.test"))[0] == 400                                # id seguro (pastas)
    assert c("POST", "/api/clients", CLI("cli-a", "a.test"))[0] == 200 and c("POST", "/api/clients", CLI("cli-a", "a.test"))[0] == 409
    assert c("PUT", "/api/clients/cli-a", {**CLI("cli-a", "a2.test")})[0] == 200
    assert c("GET", "/api/clients")[1][0]["hosts"] == ["a2.test"]
    assert c("POST", "/api/jobs", {"client_id": "cli-a", "target": "https://fora.test"})[0] == 400   # fora do escopo
    assert c("POST", "/api/clients", {**CLI("cli-v", "v.test"), "valid_until": "2020-01-01", "valid_from": "2019-01-01"})[0] == 200
    assert c("POST", "/api/jobs", {"client_id": "cli-v", "target": "https://v.test"})[0] == 400       # termo vencido
    log = open(tmp / "control_audit.log").read(); assert "client_created" in log and "client_updated" in log and "job_rejected" in log
def test_approval_flow_audited_token_never_exposed(srv):
    s, b, tmp = srv; c = C(b); c.login(); c("POST", "/api/clients", CLI("cli-a", "a.test"))
    st, d, _ = c("POST", "/api/jobs", {"client_id": "cli-a", "target": "https://a.test", "goal": "auditoria com teste ativo"})
    assert st == 200 and d["status"] == "aguardando_aprovacao"; jid = d["id"]
    aps = [a for a in c("GET", "/api/approvals")[1] if a["job_id"] == jid]; assert aps and all(a["status"] == "pendente" for a in aps)
    assert c("POST", f"/api/approvals/{aps[0]['id']}", {"decision": "approve", "reason": ""})[0] == 400    # justificativa obrigatória
    for a in aps: assert c("POST", f"/api/approvals/{a['id']}", {"decision": "approve", "reason": "termo TERMO-T-1 cláusula 3"})[0] == 200
    assert c("POST", f"/api/approvals/{aps[0]['id']}", {"decision": "deny", "reason": "x"})[0] == 400       # já decidida
    j = s.app.store.q("SELECT * FROM jobs WHERE id=?", (jid,), one=True); assert j["status"] == "na_fila" and j["approval_token"]
    ap = json.load(open(tmp / "clients" / "cli-a" / "jobs" / str(jid) / "approvals.json"))["approvals"][0]
    assert ap["approved_by"] == "dono" and ap["client_id"] == "cli-a" and ap["token"] == j["approval_token"]
    everything = json.dumps([c("GET", p)[1] for p in ("/api/approvals", "/api/jobs", f"/api/jobs/{jid}", "/api/dashboard", "/api/audit")])
    assert j["approval_token"] not in everything
    # o gate do NÚCLEO aceita esse token só para esse cliente/alvo
    from cyberswarm.hacker.approvals import ApprovalGate
    from cyberswarm.audit import Audit
    g = ApprovalGate(str(tmp / "clients" / "cli-a" / "jobs" / str(jid) / "approvals.json"), Audit(str(tmp / "g.log")))
    assert g.check("active_client_test", "https://a.test", j["approval_token"], "cli-a") and not g.check("active_client_test", "https://b.test", j["approval_token"], "cli-a")
    log = open(tmp / "control_audit.log").read(); assert "approval_requested" in log and "approval_granted" in log and "termo TERMO-T-1" in log
def test_deny_runs_passive_only(srv):
    s, b, tmp = srv; c = C(b); c.login(); c("POST", "/api/clients", CLI("cli-a", "a.test"))
    jid = c("POST", "/api/jobs", {"client_id": "cli-a", "target": "https://a.test", "goal": "auditoria ativa"})[1]["id"]
    for a in c("GET", "/api/approvals")[1]: c("POST", f"/api/approvals/{a['id']}", {"decision": "deny", "reason": "fora da janela"})
    j = s.app.store.q("SELECT * FROM jobs WHERE id=?", (jid,), one=True)
    assert j["status"] == "na_fila" and not j["approval_token"] and not os.path.exists(tmp / "clients" / "cli-a" / "jobs" / str(jid) / "approvals.json")
    assert "approval_denied" in open(tmp / "control_audit.log").read()
def test_client_separation(srv):
    s, b, tmp = srv; o = C(b); o.login()
    for cid in ("cli-a", "cli-b"): o("POST", "/api/clients", CLI(cid, cid + ".test"))
    ja = o("POST", "/api/jobs", {"client_id": "cli-a", "target": "https://cli-a.test"})[1]["id"]
    jb = o("POST", "/api/jobs", {"client_id": "cli-b", "target": "https://cli-b.test"})[1]["id"]
    da, db_ = tmp / "clients" / "cli-a" / "jobs" / str(ja), tmp / "clients" / "cli-b" / "jobs" / str(jb)
    assert da.is_dir() and db_.is_dir()
    (db_ / "report-9-x.pdf").write_bytes(b"%PDF-1.4 segredo do cliente B")
    v = C(b); v.login("leitor")   # restrito a cli-a
    assert [x["id"] for x in v("GET", "/api/clients")[1]] == ["cli-a"]
    assert {j["client_id"] for j in v("GET", "/api/jobs")[1]} == {"cli-a"}
    assert v("GET", f"/api/jobs/{jb}")[0] == 404 and v("GET", f"/api/jobs/{jb}/files/report-9-x.pdf")[0] == 404 and v("GET", f"/api/jobs/{jb}/findings")[0] == 404
    assert all(a["client_id"] == "cli-a" for a in v("GET", "/api/approvals")[1])
    assert o("GET", f"/api/compare?a={ja}&b={jb}")[0] == 400                         # não mistura clientes
    st, body, h = o("GET", f"/api/jobs/{jb}/files/report-9-x.pdf?dl=1"); assert st == 200 and "attachment" in h["Content-Disposition"]
    assert o("GET", f"/api/jobs/{jb}/files/..%2F..%2Fcontrol.db")[0] == 404
def test_finance_manual_only(srv):
    _, b, _ = srv; c = C(b); c.login()
    d = c("GET", "/api/finance")[1]; assert d["lancamentos"] == [] and d["saldo_centavos"] == 0   # nada inventado
    assert c("POST", "/api/finance", {"date": "2026-11-02", "kind": "receita", "amount": "450.50", "description": "piloto"})[0] == 200
    assert c("POST", "/api/finance", {"date": "2026-11-02", "kind": "despesa", "amount": "-1", "description": "x"})[0] == 400
    d = c("GET", "/api/finance")[1]; assert d["totais_centavos"]["receita"] == 45050 and d["saldo_centavos"] == 45050
def test_tools_toggle_uses_core_disable(srv, monkeypatch):
    _, b, _ = srv; c = C(b); c.login(); monkeypatch.delenv("CYBERSWARM_DISABLE_TOOLS", raising=False)
    assert c("POST", "/api/tools", {"disabled": ["nuclei", "rm -rf"]})[1]["disabled"] == ["nuclei"]
    from cyberswarm.tools import which
    assert which("nuclei") is None and os.environ["CYBERSWARM_DISABLE_TOOLS"] == "nuclei"
    c("POST", "/api/tools", {"disabled": []}); assert "CYBERSWARM_DISABLE_TOOLS" not in os.environ
def test_bind_localhost_default_and_lan_requires_flag(tmp_path):
    with pytest.raises(ValueError): S.serve(str(tmp_path), host="0.0.0.0", port=free_port(), autostart=False, block=False)
    s = S.serve(str(tmp_path), port=free_port(), autostart=False, block=False)
    try: assert s.server_address[0] == "127.0.0.1"
    finally: s.shutdown()
def test_pwa_manifest_sw_icons_and_no_secrets(srv):
    _, b, _ = srv; c = C(b)
    st, m, h = c("GET", "/manifest.json"); assert st == 200 and h["Content-Type"].startswith("application/manifest+json")
    for k in ("name", "short_name", "start_url", "scope", "display", "icons", "theme_color", "background_color"): assert k in m
    assert m["display"] == "standalone" and m["lang"] == "pt-BR"
    from PIL import Image; import io
    sizes = set()
    for i in m["icons"]:
        st, raw, _ = c("GET", i["src"]); im = Image.open(io.BytesIO(raw)); assert f"{im.width}x{im.height}" == i["sizes"]; sizes.add(i["sizes"])
    assert {"192x192", "512x512"} <= sizes and any("maskable" in i.get("purpose", "") for i in m["icons"])
    st, sw, h = c("GET", "/sw.js"); sw = sw.decode()
    assert st == 200 and "javascript" in h["Content-Type"] and 'startsWith("/api/")' in sw and "fetch" in sw
    st, html, h = c("GET", "/"); html = html.decode(); assert 'rel="manifest"' in html and "<script>" not in html and "script-src 'self'" in h["Content-Security-Policy"]
    static = os.path.join(os.path.dirname(S.__file__), "static")
    js = open(os.path.join(static, "app.js")).read()
    assert "localStorage" not in js and "sessionStorage" not in js and PW not in js and not re.search(r"(api[_-]?key|secret)\s*[:=]\s*['\"]\w", js, re.I)
def test_lab_mission_end_to_end_via_queue(tmp_path):
    st = Store(str(tmp_path / "control.db")); st.add_user("dono", PW, "owner"); del st
    port = free_port(); s = S.serve(str(tmp_path), port=port, workers=1, block=False); b = f"http://127.0.0.1:{port}"
    try:
        c = C(b); c.login(); jid = c("POST", "/api/jobs", {"client_id": "_lab", "goal": "verificar cabeçalhos web e TLS"})[1]["id"]
        for _ in range(240):
            j = c("GET", f"/api/jobs/{jid}")[1]
            if j["job"]["status"] in ("concluida", "erro"): break
            time.sleep(0.5)
        assert j["job"]["status"] == "concluida", j["job"]
        assert j["tasks"] and j["mensagens"] and any(f.endswith(".pdf") for f in j["arquivos"])
        fs = c("GET", f"/api/jobs/{jid}/findings")[1]; assert fs and all("abs" not in (f.get("proof") or {}) for f in fs)
        assert any(f["status"] == "confirmado" for f in fs)
        assert (tmp_path / "clients" / "_lab" / "jobs" / str(jid) / "cyberswarm.db").exists()
    finally: s.shutdown()
def test_restart_resumes_interrupted_job(tmp_path):
    st = Store(str(tmp_path / "control.db")); st.x("INSERT INTO jobs(client_id,kind,status,created,attempts) VALUES('_lab','hacker','executando',0,0)")
    from cyberswarm.control.worker import Worker
    from cyberswarm.audit import Audit
    Worker(st, str(tmp_path), Audit(str(tmp_path / "a.log")), autostart=False)
    j = st.q("SELECT status,attempts FROM jobs", one=True)
    assert j["status"] == "na_fila" and j["attempts"] == 1
def test_restart_gives_up_after_max_attempts(tmp_path, monkeypatch):
    monkeypatch.setenv("CYBERSWARM_JOB_ATTEMPTS", "2")
    import importlib, cyberswarm.control.worker as W; importlib.reload(W)
    st = Store(str(tmp_path / "control.db")); st.x("INSERT INTO jobs(client_id,kind,status,created,attempts) VALUES('_lab','hacker','executando',0,1)")
    from cyberswarm.audit import Audit
    W.Worker(st, str(tmp_path), Audit(str(tmp_path / "a.log")), autostart=False)
    assert st.q("SELECT status FROM jobs", one=True)["status"] == "erro"


def test_chat_mission_lab(srv):
    _, b, _ = srv; c = C(b); c.login()
    tid = c("POST", "/api/chat/threads", {"client_id": "_lab", "title": "t"})[1]["id"]
    r = c("POST", f"/api/chat/threads/{tid}/messages", {"content": "verificar cabeçalhos TLS do laboratório"})[1]
    assert r["meta"]["intent"] == "mission" and r["meta"].get("job")
    msgs = c("GET", f"/api/chat/threads/{tid}")[1]["messages"]
    assert any(m["role"] == "assistant" for m in msgs)
def test_settings_no_key_echo(srv):
    _, b, _ = srv; c = C(b); c.login()
    c("POST", "/api/settings", {"mode": "none", "api_key": "sk-secret-should-not-echo", "deterministic": False})
    s = c("GET", "/api/settings")[1]
    assert "api_key" not in s and "api_key_enc" not in s and s["has_api_key"] is True
def test_job_dedupe(srv):
    _, b, _ = srv; c = C(b); c.login()
    a = c("POST", "/api/jobs", {"kind": "hacker", "client_id": "_lab", "goal": "mesmo objetivo dedupe xyz"})[1]
    b2 = c("POST", "/api/jobs", {"kind": "hacker", "client_id": "_lab", "goal": "mesmo objetivo dedupe xyz"})[1]
    assert a["id"] == b2["id"]
def test_tls_self_signed(tmp_path):
    from cyberswarm.control.tlsutil import ensure_self_signed, ssl_context
    c, k = ensure_self_signed(str(tmp_path / "tls"))
    assert os.path.exists(c) and os.stat(k).st_mode & 0o777 == 0o600
    ssl_context(c, k)
def test_no_shell_still(srv):
    _, b, _ = srv; c = C(b); c.login()
    for path in ("/api/shell", "/api/exec", "/api/command", "/api/terminal"):
        assert c("GET", path)[0] == 404
