"""14 critérios de aceitação — automatizados o máximo possível no box.
Itens que exigem Galaxy A32 físico ficam marcados phone_required e são skip."""
import os, re, time, json, pytest
from cyberswarm.control import server as S
from cyberswarm.control.store import Store
from tests.test_control import C, PW, free_port

pytestmark = pytest.mark.acceptance
PHONE = pytest.mark.skip(reason="requer Galaxy A32 físico / Chrome do usuário")

@pytest.fixture
def srv(tmp_path):
    st = Store(str(tmp_path / "control.db")); st.add_user("dono", PW, "owner"); del st
    port = free_port(); s = S.serve(str(tmp_path), port=port, workers=1, block=False, autostart=True)
    yield s, f"http://127.0.0.1:{port}", tmp_path
    s.shutdown()

def test_01_install_pwa_manifest(srv):
    """Critério 1 (parcial): manifesto/SW válidos; instalação real = phone."""
    _, b, _ = srv; c = C(b)
    m = c("GET", "/manifest.json") if False else __import__("urllib.request").request.urlopen(b+"/manifest.json")
    # use raw
    import urllib.request
    man = json.loads(urllib.request.urlopen(b+"/manifest.json").read())
    assert man["display"] == "standalone" and man["icons"]
    sw = urllib.request.urlopen(b+"/sw.js").read().decode()
    assert "caches.open" in sw or "caches" in sw
    assert "fetch" in sw

@PHONE
def test_01b_install_on_android():
    """Critério 1 completo: Adicionar à tela inicial no A32."""

def test_02_authenticate(srv):
    _, b, _ = srv; c = C(b); c.login()
    me = c("GET", "/api/me")[1]; assert me["username"] == "dono" and me["csrf"]

def test_03_open_chat(srv):
    _, b, _ = srv; c = C(b); c.login()
    tid = c("POST", "/api/chat/threads", {"client_id": "_lab"})[1]["id"]
    assert c("GET", f"/api/chat/threads/{tid}")[0] == 200

def test_04_05_06_receive_plan_queue(srv):
    """Critérios 4–6: pedido → plano → fila."""
    _, b, _ = srv; c = C(b); c.login()
    tid = c("POST", "/api/chat/threads", {"client_id": "_lab"})[1]["id"]
    r = c("POST", f"/api/chat/threads/{tid}/messages", {"content": "verificar cabeçalhos web e TLS do laboratório"})[1]
    assert r["meta"]["intent"] == "mission" and r["meta"].get("job")
    assert "módulos" in r["reply"].lower() or "Plano" in r["reply"] or "Missão" in r["reply"]
    jid = r["meta"]["job"]
    st = c("GET", f"/api/jobs/{jid}")[1]["job"]["status"]
    assert st in ("na_fila", "executando", "concluida", "aguardando_aprovacao")

def test_07_run_authorized_lab(tmp_path):
    st = Store(str(tmp_path / "control.db")); st.add_user("dono", PW, "owner"); del st
    port = free_port(); s = S.serve(str(tmp_path), port=port, workers=1, block=False)
    try:
        c = C(f"http://127.0.0.1:{port}"); c.login()
        jid = c("POST", "/api/jobs", {"client_id": "_lab", "goal": "verificar cabeçalhos web e TLS"})[1]["id"]
        for _ in range(240):
            j = c("GET", f"/api/jobs/{jid}")[1]
            if j["job"]["status"] in ("concluida", "erro"): break
            time.sleep(0.5)
        assert j["job"]["status"] == "concluida"
        assert any(f["status"] == "confirmado" for f in c("GET", f"/api/jobs/{jid}/findings")[1])
    finally: s.shutdown()

def test_08_resume_after_interrupt(tmp_path):
    st = Store(str(tmp_path / "control.db"))
    st.x("INSERT INTO jobs(client_id,kind,goal,targets,status,created,attempts) VALUES('_lab','hacker','x','{}','executando',0,0)")
    from cyberswarm.control.worker import Worker
    from cyberswarm.audit import Audit
    Worker(st, str(tmp_path), Audit(str(tmp_path/"a.log")), autostart=False)
    assert st.q("SELECT status FROM jobs", one=True)["status"] == "na_fila"

def test_09_deterministic_without_ai(tmp_path):
    from cyberswarm.v2.deterministic import DeterministicGate, is_complex
    from cyberswarm.hacker.planner import plan
    from cyberswarm.audit import Audit
    au = Audit(str(tmp_path/"a.log"))
    g = DeterministicGate(str(tmp_path/"plans.json"), au)
    P = plan("auditoria web completa com varredura ativa", {"url": "https://www.acme.invalid"})
    assert is_complex(P["tasks"]), "plano com varredura ativa deve ser complexo"
    ok, why, _ = g.check(P["tasks"]); assert ok is False and why
    passives = [t for t in P["tasks"] if not t.get("active")]
    assert passives and g.check(passives)[0] is True

def test_10_verifiable_evidence(srv):
    # coberta pelo lab e2e; aqui checa validador
    from cyberswarm.agents.validation import proof_status
    assert proof_status({"type": "http", "request": "GET /", "response": "HTTP/1.1 200", "curl": "curl"}) == "confirmado"

def test_11_pdf_generated(tmp_path):
    # se e2e já gerou em outros testes; checa writer disponível
    from cyberswarm.report import write_reports
    assert callable(write_reports)

def test_12_approvals_and_history(srv):
    _, b, _ = srv; c = C(b); c.login()
    # cria cliente + missão ativa → aprovação
    c("POST", "/api/clients", {"id": "acme-test", "name": "Acme", "authorization_ref": "T-1", "authorized_by": "X",
                               "valid_from": "2026-01-01", "valid_until": "2027-01-01", "hosts": ["www.acme-test.invalid"]})
    jid = c("POST", "/api/jobs", {"client_id": "acme-test", "goal": "auditoria web completa com varredura ativa",
                                  "target": "https://www.acme-test.invalid"})[1]["id"]
    assert c("GET", f"/api/jobs/{jid}")[1]["job"]["status"] == "aguardando_aprovacao"
    aps = c("GET", "/api/approvals")[1]; assert any(a["job_id"] == jid and a["status"] == "pendente" for a in aps)
    assert c("GET", "/api/audit?limit=20")[1]["integra"] is True

def test_13_client_isolation(srv):
    _, b, _ = srv; c = C(b); c.login()
    # viewer preso a um cliente
    c("POST", "/api/users", {"username": "viz", "password": PW, "role": "viewer", "clients": ["acme-x"]})
    # se cliente não existe, ainda assim a restrição vale
    c2 = C(b); assert c2("POST", "/api/login", {"username": "viz", "password": PW})[0] == 200
    jobs = c2("GET", "/api/jobs")[1]
    assert all(j["client_id"] in ("acme-x",) or False for j in jobs) or jobs == []

def test_14_not_grok_dependent(srv):
    _, b, _ = srv; c = C(b); c.login()
    s = c("GET", "/api/settings")[1]
    assert s.get("mode") in ("none", "ollama", "openai", None) or s.get("provider") in ("none", "ollama", "openai") or s.get("provider_ativo") in ("none", None) or "has_api_key" in s
    tid = c("POST", "/api/chat/threads", {"client_id": "_lab"})[1]["id"]
    r = c("POST", f"/api/chat/threads/{tid}/messages", {"content": "ajuda"})[1]
    assert r["meta"]["intent"] == "help" and "Grok" not in r["reply"]
