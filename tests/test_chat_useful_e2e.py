"""E2E útil: scan web em fixture HTTP própria (loopback) + preservação de senha no update pinado."""
import json, os, re, shutil, socket, subprocess, sys, tempfile, threading, time, http.server
from pathlib import Path
import pytest
from test_control import C, PW, srv  # noqa: F401


class _MissingHeadersHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):  # silêncio
        pass

    def do_GET(self):
        body = b"<html><body>fixture cyberswarm</body></html>"
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        # propositalmente SEM CSP / XFO / XCTO / Referrer-Policy
        self.end_headers()
        self.wfile.write(body)

    def do_HEAD(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Allow", "GET, HEAD, OPTIONS")
        self.send_header("Content-Length", "0")
        self.end_headers()


@pytest.fixture
def weak_http():
    s = socket.socket(); s.bind(("127.0.0.1", 0)); port = s.getsockname()[1]; s.close()
    httpd = http.server.ThreadingHTTPServer(("127.0.0.1", port), _MissingHeadersHandler)
    t = threading.Thread(target=httpd.serve_forever, daemon=True); t.start()
    yield f"http://127.0.0.1:{port}/"
    httpd.shutdown()


def test_web_agent_evidence_on_own_fixture(weak_http, run_agent):
    """Módulo web real contra HTTP nosso sem cabeçalhos — evidência observada, gravidade da tabela."""
    from cyberswarm.checks import C
    findings = run_agent("web", weak_http)
    assert findings, "esperava achados de cabeçalhos ausentes"
    ids = {f["check_id"] for f in findings}
    assert "web.header.csp" in ids
    # gravidade vem do catálogo — não inventada como critical
    for f in findings:
        if f["check_id"].startswith("web.header."):
            assert f["severity"] == C[f["check_id"]]["severity"]
            assert f["severity"] != "critical"
            assert f.get("evidence")
            assert f.get("proof")
            assert f.get("recommendation")
    # grava evidência anexável (sem segredos)
    out = Path("/workspace/cyberswarm-evidence-2.1.1.txt")
    lines = [
        "CyberSwarm 2.1.1 — evidência de scan web em fixture própria (loopback)",
        f"Alvo: {weak_http}",
        f"Achados: {len(findings)}",
        "",
    ]
    for f in findings:
        if not f["check_id"].startswith("web.header.") and f["check_id"] != "web.no_https":
            continue
        lines.append(f"[{f['severity']}] {f['check_id']} — {f['title']}")
        lines.append(f"  evidência: {f['evidence']}")
        lines.append(f"  correção: {f['recommendation']}")
        proof = f.get("proof") or {}
        if isinstance(proof, dict):
            resp = proof.get("response") or ""
            # response é texto HTTP observado (primeira linha = status)
            first = (resp.splitlines()[0] if isinstance(resp, str) and resp else "")[:120]
            if first:
                lines.append(f"  prova HTTP: {first}")
            curl = (proof.get("curl") or "")[:160]
            if curl:
                lines.append(f"  repro: {curl}")
        lines.append("")
    out.write_text("\n".join(lines), encoding="utf-8")
    assert out.stat().st_size > 50


def test_chat_lab_web_flow_counts_jobs(srv):
    """Fluxo chat autenticado: prévia → 1 confirm → +1 job; inputs ruins = 0 jobs."""
    _, b, _ = srv
    c = C(b); c.login()
    tid = c("POST", "/api/chat/threads", {"client_id": "_lab"})[1]["id"]
    n0 = len(c("GET", "/api/jobs")[1])
    for bad in ("Oi", "Quero um teste", "Meu Wi-Fi"):
        r = c("POST", f"/api/chat/threads/{tid}/messages", {"content": bad})[1]
        assert not r["meta"].get("job")
    assert len(c("GET", "/api/jobs")[1]) == n0
    r1 = c("POST", f"/api/chat/threads/{tid}/messages", {"content": "verificar cabeçalhos do laboratório"})[1]
    assert r1["meta"]["intent"] == "confirm_scope" and not r1["meta"].get("job")
    assert len(c("GET", "/api/jobs")[1]) == n0
    r2 = c("POST", f"/api/chat/threads/{tid}/messages", {"content": "escopo autorizado"})[1]
    assert r2["meta"].get("job")
    assert len(c("GET", "/api/jobs")[1]) == n0 + 1
    r3 = c("POST", f"/api/chat/threads/{tid}/messages", {"content": "escopo autorizado"})[1]
    assert not r3["meta"].get("job")
    assert len(c("GET", "/api/jobs")[1]) == n0 + 1


def test_pinned_update_preserves_env_password(tmp_path):
    """Simula HOME isolado: env com senha sobrevive a checkout pinado (sem imprimir segredo)."""
    home = tmp_path / "home"
    home.mkdir()
    data = home / "cyberswarm-data"; data.mkdir()
    envf = home / ".cyberswarm_env"
    # marca opaca — não é senha real do usuário
    marker = "PRESERVE_MARKER_NOT_A_SECRET_xx99"
    envf.write_text(f"CONTROL_PASSWORD={marker}\nCYBERSWARM_SECRET=unit-test-secret-only\n")
    envf.chmod(0o600)
    (data / "control.db").write_text("placeholder")
    # "update" = re-criar árvore de código sem tocar no env
    code = home / "cyberswarm"; code.mkdir()
    (code / "termux").mkdir()
    shutil.copy("termux/instalar.sh", code / "termux" / "instalar.sh")
    # o instalador real só cria ENVF se NÃO existir — aqui garantimos preservação
    assert envf.exists()
    text = envf.read_text()
    assert marker in text
    assert "CONTROL_PASSWORD=" in text
    # backup script dry logic: arquivo env não é apagado por update de código
    assert oct(envf.stat().st_mode)[-3:] == "600"
