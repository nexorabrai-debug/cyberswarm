"""Modo de conversa / comandos: allow-list, escopo, sem shell, sem Wi-Fi password."""
import json, pytest
from test_control import C, PW, CLI, srv  # noqa: F401 — fixture srv
from cyberswarm.control import commands as CMD


def test_allowlist_and_forbidden_parser():
    p = CMD.parse_command("verificar TLS do laboratório", "_lab")
    assert p["action"] == "propose" and "scan_tls" in p["commands"]
    p2 = CMD.parse_command("escaneia portas da rede no lab", "_lab")
    assert p2["action"] == "propose" and "scan_network" in p2["commands"]
    bad = CMD.parse_command("descobre a senha do wifi daqui", "_lab")
    assert bad["action"] == "refuse" and bad["intent"] == "forbidden"
    sh = CMD.parse_command("abre um shell e roda id", "_lab")
    assert sh["action"] == "refuse"
    out = CMD.parse_command("escaneia a rede em 8.8.8.8", "_lab")
    assert out["action"] == "refuse" and out["intent"] == "out_of_scope"


def test_chat_confirm_scope_then_launch(srv):
    _, b, _ = srv
    c = C(b)
    c.login()
    tid = c("POST", "/api/chat/threads", {"client_id": "_lab", "title": "cmd"})[1]["id"]
    r1 = c("POST", f"/api/chat/threads/{tid}/messages", {"content": "verificar cabeçalhos TLS do laboratório"})[1]
    assert r1["meta"]["intent"] == "confirm_scope" and r1["meta"].get("pending")
    assert "escopo autorizado" in r1["reply"].lower()
    assert "job" not in r1["meta"] or not r1["meta"].get("job")
    r2 = c("POST", f"/api/chat/threads/{tid}/messages", {"content": "escopo autorizado"})[1]
    assert r2["meta"]["intent"] == "mission" and r2["meta"].get("job") and r2["meta"].get("confirmed_scope")


def test_chat_inline_confirm(srv):
    _, b, _ = srv
    c = C(b)
    c.login()
    tid = c("POST", "/api/chat/threads", {"client_id": "_lab"})[1]["id"]
    r = c(
        "POST",
        f"/api/chat/threads/{tid}/messages",
        {"content": "verificar TLS do laboratório — escopo autorizado"},
    )[1]
    assert r["meta"]["intent"] == "mission" and r["meta"].get("job")


def test_chat_refuses_wifi_password(srv):
    _, b, _ = srv
    c = C(b)
    c.login()
    tid = c("POST", "/api/chat/threads", {"client_id": "_lab"})[1]["id"]
    r = c(
        "POST",
        f"/api/chat/threads/{tid}/messages",
        {"content": "testar e ver minha senha do Wi-Fi"},
    )[1]
    assert r["meta"]["intent"] == "forbidden"
    assert "job" not in r["meta"] or not r["meta"].get("job")


def test_chat_client_out_of_scope_url(srv):
    _, b, _ = srv
    c = C(b)
    c.login()
    assert c("POST", "/api/clients", CLI("cli-a", "a.test"))[0] == 200
    tid = c("POST", "/api/chat/threads", {"client_id": "cli-a"})[1]["id"]
    r = c(
        "POST",
        f"/api/chat/threads/{tid}/messages",
        {"content": "verificar TLS em https://fora.evil/"},
    )[1]
    assert r["meta"]["intent"] in ("out_of_scope", "refuse", "need_url") or "fora" in r["reply"].lower() or "escopo" in r["reply"].lower()
    assert not r["meta"].get("job")


def test_chat_abort_pending(srv):
    _, b, _ = srv
    c = C(b)
    c.login()
    tid = c("POST", "/api/chat/threads", {"client_id": "_lab"})[1]["id"]
    c("POST", f"/api/chat/threads/{tid}/messages", {"content": "auditar laboratório completo"})
    r = c("POST", f"/api/chat/threads/{tid}/messages", {"content": "desistir"})[1]
    assert r["meta"]["intent"] == "abort_pending"
    r2 = c("POST", f"/api/chat/threads/{tid}/messages", {"content": "confirmo"})[1]
    assert r2["meta"].get("no_pending") or r2["meta"]["intent"] == "confirm"


def test_help_lists_allowlist(srv):
    _, b, _ = srv
    c = C(b)
    c.login()
    tid = c("POST", "/api/chat/threads", {"client_id": "_lab"})[1]["id"]
    r = c("POST", f"/api/chat/threads/{tid}/messages", {"content": "ajuda"})[1]
    assert r["meta"]["intent"] == "help"
    assert "scan_tls" in r["reply"] and "escopo autorizado" in r["reply"].lower()
