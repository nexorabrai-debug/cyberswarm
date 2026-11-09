"""Chat de comandos 2.1.1: sem missão em saudação/vago/código; Wi-Fi explica limite; confirm 1x."""
import json, time, http.server, threading, pytest
from test_control import C, PW, CLI, srv  # noqa: F401
from cyberswarm.control import commands as CMD


def _jobs(c):
    return c("GET", "/api/jobs")[1]


def _njobs(c):
    return len(_jobs(c))


def test_parser_greetings_vague_wifi_code_never_propose():
    for msg in ("Oi", "oi", "olá", "Olá", "eai", "bom dia", "D", "Quero um teste", "quero um teste", "Meu Wi-Fi", "meu wifi"):
        p = CMD.parse_command(msg, "_lab")
        assert p["action"] != "propose", (msg, p)
        assert p["action"] in ("greet", "clarify", "refuse", "none"), (msg, p)
    wifi = CMD.parse_command("Meu Wi-Fi", "_lab")
    assert wifi["action"] == "refuse" and wifi["intent"] == "forbidden"
    assert "127.0.0.1" in wifi["error"] or "roteador" in wifi["error"].lower()
    code = CMD.parse_command("import os\ndef main():\n    print(os.system('id'))\n", "_lab")
    assert code["action"] == "refuse" and code["intent"] == "code_paste"
    good = CMD.parse_command("verificar cabeçalhos do laboratório", "_lab")
    assert good["action"] == "propose" and "scan_web" in good["commands"]


def test_api_greetings_and_vague_never_enqueue(srv):
    _, b, _ = srv
    c = C(b)
    c.login()
    tid = c("POST", "/api/chat/threads", {"client_id": "_lab", "title": "safe"})[1]["id"]
    before = _njobs(c)
    for msg in ("Oi", "oi", "olá", "Quero um teste", "D", "Meu Wi-Fi"):
        r = c("POST", f"/api/chat/threads/{tid}/messages", {"content": msg})[1]
        assert not r["meta"].get("job"), (msg, r)
        assert r["meta"]["intent"] in ("greet", "vague", "unknown", "forbidden", "clarify")
    # código Python multilinha
    py = "import sys\n\ndef run():\n    return sys.argv\n"
    r = c("POST", f"/api/chat/threads/{tid}/messages", {"content": py})[1]
    assert not r["meta"].get("job") and r["meta"]["intent"] == "code_paste"
    after = _njobs(c)
    assert after == before


def test_stale_pending_greet_then_confirm_does_not_launch(srv):
    """Bug 2.1.0: pending de 'teste' + 'Oi' + 'confirmo' não pode criar missão."""
    _, b, _ = srv
    c = C(b)
    c.login()
    tid = c("POST", "/api/chat/threads", {"client_id": "_lab"})[1]["id"]
    before = _njobs(c)
    # pedido vago NÃO cria pending
    r0 = c("POST", f"/api/chat/threads/{tid}/messages", {"content": "Quero um teste"})[1]
    assert r0["meta"]["intent"] in ("vague", "unknown") and not r0["meta"].get("pending")
    # cria pending legítimo
    r1 = c("POST", f"/api/chat/threads/{tid}/messages", {"content": "verificar TLS do laboratório"})[1]
    assert r1["meta"]["intent"] == "confirm_scope" and r1["meta"].get("pending")
    fp = r1["meta"]["fp"]
    # saudação descarta pending
    r2 = c("POST", f"/api/chat/threads/{tid}/messages", {"content": "Oi"})[1]
    assert r2["meta"]["intent"] == "greet" and r2["meta"].get("cleared_pending")
    r3 = c("POST", f"/api/chat/threads/{tid}/messages", {"content": "confirmo"})[1]
    assert r3["meta"].get("no_pending") or r3["meta"]["intent"] == "confirm"
    assert not r3["meta"].get("job")
    assert _njobs(c) == before


def test_confirm_enqueues_exactly_once_bound_to_fp(srv):
    _, b, _ = srv
    c = C(b)
    c.login()
    tid = c("POST", "/api/chat/threads", {"client_id": "_lab"})[1]["id"]
    before = _njobs(c)
    r1 = c("POST", f"/api/chat/threads/{tid}/messages", {"content": "verificar cabeçalhos do laboratório"})[1]
    assert r1["meta"]["intent"] == "confirm_scope" and r1["meta"].get("fp")
    assert "Prévia" in r1["reply"] or "alvo" in r1["reply"].lower()
    assert before == _njobs(c)  # ainda não enfileirou
    r2 = c("POST", f"/api/chat/threads/{tid}/messages", {"content": "escopo autorizado"})[1]
    assert r2["meta"]["intent"] == "mission" and r2["meta"].get("job") and r2["meta"].get("confirmed_scope")
    assert r2["meta"].get("fp") == r1["meta"]["fp"]
    mid = _njobs(c)
    assert mid == before + 1
    # segunda confirmação sem novo pedido não cria outra
    r3 = c("POST", f"/api/chat/threads/{tid}/messages", {"content": "escopo autorizado"})[1]
    assert not r3["meta"].get("job")
    assert _njobs(c) == mid


def test_new_propose_replaces_old_pending(srv):
    _, b, _ = srv
    c = C(b)
    c.login()
    tid = c("POST", "/api/chat/threads", {"client_id": "_lab"})[1]["id"]
    r1 = c("POST", f"/api/chat/threads/{tid}/messages", {"content": "verificar TLS do laboratório"})[1]
    fp1 = r1["meta"]["fp"]
    r2 = c("POST", f"/api/chat/threads/{tid}/messages", {"content": "verificar cabeçalhos do laboratório"})[1]
    fp2 = r2["meta"]["fp"]
    assert fp1 != fp2
    before = _njobs(c)
    r3 = c("POST", f"/api/chat/threads/{tid}/messages", {"content": "confirmo"})[1]
    assert r3["meta"].get("job") and r3["meta"]["fp"] == fp2
    assert _njobs(c) == before + 1


def test_status_reports_real_tasks(srv):
    _, b, _ = srv
    c = C(b)
    c.login()
    tid = c("POST", "/api/chat/threads", {"client_id": "_lab"})[1]["id"]
    r = c("POST", f"/api/chat/threads/{tid}/messages", {"content": "status"})[1]
    assert r["meta"]["intent"] == "status"
    assert "Fila" in r["reply"] or "nenhuma" in r["reply"].lower()
    assert "count" in r["meta"]


def test_help_friendly_no_raw_dump_required(srv):
    _, b, _ = srv
    c = C(b)
    c.login()
    tid = c("POST", "/api/chat/threads", {"client_id": "_lab"})[1]["id"]
    r = c("POST", f"/api/chat/threads/{tid}/messages", {"content": "ajuda"})[1]
    assert r["meta"]["intent"] == "help"
    assert "assistente de comandos" in r["reply"].lower() or "regras" in r["reply"].lower()
    assert "escopo autorizado" in r["reply"].lower()
    assert "Wi-Fi" in r["reply"] or "wi-fi" in r["reply"].lower()


def test_provider_none_labeled_honestly(srv):
    _, b, _ = srv
    c = C(b)
    c.login()
    tid = c("POST", "/api/chat/threads", {"client_id": "_lab"})[1]["id"]
    r1 = c("POST", f"/api/chat/threads/{tid}/messages", {"content": "checar TLS do laboratório"})[1]
    assert "sem LLM" in r1["reply"] or "assistente de comandos" in r1["reply"].lower()
    r2 = c("POST", f"/api/chat/threads/{tid}/messages", {"content": "escopo autorizado"})[1]
    assert r2["meta"].get("job")
    assert "sem LLM" in (r2.get("meta", {}).get("provider_label") or r2["reply"]).lower() or r2["meta"].get("provider") == "none"


def test_chat_confirm_scope_then_launch(srv):
    _, b, _ = srv
    c = C(b)
    c.login()
    tid = c("POST", "/api/chat/threads", {"client_id": "_lab", "title": "cmd"})[1]["id"]
    r1 = c("POST", f"/api/chat/threads/{tid}/messages", {"content": "verificar cabeçalhos TLS do laboratório"})[1]
    assert r1["meta"]["intent"] == "confirm_scope" and r1["meta"].get("pending")
    assert "escopo autorizado" in r1["reply"].lower()
    assert not r1["meta"].get("job")
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
    assert not r["meta"].get("job")


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
    c("POST", f"/api/chat/threads/{tid}/messages", {"content": "auditoria completa do laboratório"})
    r = c("POST", f"/api/chat/threads/{tid}/messages", {"content": "desistir"})[1]
    assert r["meta"]["intent"] == "abort_pending"
    r2 = c("POST", f"/api/chat/threads/{tid}/messages", {"content": "confirmo"})[1]
    assert r2["meta"].get("no_pending") or r2["meta"]["intent"] == "confirm"


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
