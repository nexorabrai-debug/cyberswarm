import datetime, json, os, pytest
from conftest import LABDATA, free_port
from cyberswarm.scope import Scope, OutOfScope, resolve_scope, load_clients, client_scope
from cyberswarm.audit import Audit, verify
from cyberswarm.net import Net, BudgetExceeded
from cyberswarm.cli import main
def test_lab_allowed():
    s = Scope.lab(); assert s.check("http://127.0.0.1:8088") and s.check(os.path.join(LABDATA, "src"))
@pytest.mark.parametrize("t", ["https://example.com", "http://10.0.0.5", "ftp://127.0.0.1", "http://127.0.0.1.evil.com", "/etc/passwd", os.path.join(LABDATA, "..", "scope.py")])
def test_out_of_scope_rejected(t):
    with pytest.raises(OutOfScope): Scope.lab().check(t)
def test_non_lab_requires_client(tmp_path):
    with pytest.raises(OutOfScope, match="exige --client"): resolve_scope("https://example.com", str(tmp_path / "c.json"))
def _clients(tmp_path, **over):
    c = {"id": "acme", "name": "ACME", "authorization_ref": "TERMO-1", "authorized_by": "Dona", "valid_from": "2026-01-01",
         "valid_until": "2099-01-01", "scope": {"hosts": ["www.acme.test"], "paths": []}}; c.update(over)
    p = tmp_path / "clients.json"; p.write_text(json.dumps({"clients": [c]})); return str(p)
def test_client_scope_ok_and_limited(tmp_path):
    p = _clients(tmp_path); s = resolve_scope("https://www.acme.test/", p, "acme")
    assert s.client["authorization_ref"] == "TERMO-1"
    with pytest.raises(OutOfScope): s.check("https://other.test")
    with pytest.raises(OutOfScope): resolve_scope("https://other.test", p, "acme")
def test_client_expired_or_incomplete(tmp_path):
    with pytest.raises(OutOfScope, match="validade"): resolve_scope("https://www.acme.test", _clients(tmp_path, valid_until="2020-01-01"), "acme")
    with pytest.raises(OutOfScope, match="authorization_ref"): resolve_scope("https://www.acme.test", _clients(tmp_path, authorization_ref=""), "acme")
    with pytest.raises(OutOfScope, match="não cadastrado"): resolve_scope("https://www.acme.test", _clients(tmp_path), "nope")
def test_clients_refuse_credentials(tmp_path):
    with pytest.raises(ValueError, match="credenciais"): load_clients(_clients(tmp_path, password="x"))
    with pytest.raises(ValueError): load_clients(_clients(tmp_path, scope={"hosts": [], "token": "abc"}))
def test_cli_blocks_and_audits(tmp_path, capsys):
    assert main(["--out", str(tmp_path), "scan", "--target", "https://example.com"]) == 2
    assert "BLOQUEADO" in capsys.readouterr().out
    log = (tmp_path / "audit.log").read_text(); assert "scope_denied" in log and "example.com" in log
def test_audit_chain_tamper(tmp_path):
    a = Audit(str(tmp_path / "a.log")); a.log("x", n=1); a.log("y", n=2); a.log("z", n=3)
    assert verify(str(tmp_path / "a.log")) == (True, 0)
    L = (tmp_path / "a.log").read_text().splitlines(); L[1] = L[1].replace('"n": 2', '"n": 9'); (tmp_path / "a.log").write_text("\n".join(L) + "\n")
    assert verify(str(tmp_path / "a.log"))[0] is False
def test_net_budget_rate_and_methods(tmp_path, lab_url):
    import time
    a = Audit(str(tmp_path / "a.log")); n = Net(Scope.lab(), a, rate_per_sec=10, max_requests=3)
    t0 = time.monotonic(); [n.request(lab_url) for _ in range(3)]; assert time.monotonic() - t0 >= 0.19  # 10 req/s
    with pytest.raises(BudgetExceeded): n.request(lab_url)
    with pytest.raises(PermissionError): Net(Scope.lab(), a).request(lab_url, method="DELETE")
    with pytest.raises(OutOfScope): Net(Scope.lab(), a).request("https://example.com")
    assert (tmp_path / "a.log").read_text().count('"op": "http"') == 3
def test_net_does_not_follow_redirect_off_scope(tmp_path):
    import http.server, threading
    class R(http.server.BaseHTTPRequestHandler):
        def do_GET(self): self.send_response(302); self.send_header("Location", "https://example.com/"); self.end_headers()
        def log_message(self, *a): pass
    s = http.server.ThreadingHTTPServer(("127.0.0.1", 0), R); threading.Thread(target=s.serve_forever, daemon=True).start()
    try: st, _, _ = Net(Scope.lab(), Audit(str(tmp_path / "a.log"))).request(f"http://127.0.0.1:{s.server_address[1]}/")
    finally: s.shutdown()
    assert st == 302
def test_no_plaintext_secrets_in_outputs(tmp_path):
    p = free_port(); q = free_port()
    assert main(["--out", str(tmp_path), "--no-pdf", "demo", "--port", str(p), "--tls-port", str(q)]) == 0
    blob = "".join(f.read_text(errors="ignore") for f in tmp_path.iterdir() if f.suffix in (".json", ".md", ".html", ".log"))
    for s in ("fake_lab_password", "SuperFakeLabPass123", "fake-secret-not-real-0000", "AKIAFAKEFAKEFAKE1234", "q9Z3vT7mK2pX8wR4nB6yH1cJ5fL0dG", "FAKE-LAB-KEY-NOT-REAL"):
        assert s not in blob, s
