"""API autenticada + arquivos estáticos da PWA (stdlib). Padrão: 127.0.0.1. Sem endpoint de comando/shell.
Papéis: owner (tudo) e viewer (só leitura, opcionalmente restrito a clientes). CSRF por sessão em toda requisição que altera estado."""
import datetime, hmac, json, mimetypes, os, re, shutil, time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from http.cookies import SimpleCookie
from urllib.parse import urlparse, parse_qs
from ..audit import Audit, verify as audit_verify
from ..db import DB
from ..report import compare_runs
from .store import Store
from .worker import Worker, LAB, SAFE_ID, job_dir
STATIC = os.path.join(os.path.dirname(__file__), "static")
LOOPBACK = {"127.0.0.1", "::1", "localhost"}
MAX_BODY = 64 * 1024
CSP = "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self'; frame-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'self'; form-action 'self'"
EXT_TOOLS = ["nmap", "nuclei", "semgrep", "trivy", "sslscan", "gitleaks", "testssl.sh"]
class HTTPError(Exception):
    def __init__(self, code, msg): super().__init__(msg); self.code, self.msg = code, msg
ROUTES = []
def route(method, pattern, role="viewer"):
    def d(fn): ROUTES.append((method, re.compile("^" + pattern + "$"), fn, role)); return fn
    return d
class App:
    def __init__(self, data, workers=2, autostart=True, secure_cookie=False):
        self.data = os.path.abspath(data); os.makedirs(self.data, exist_ok=True)
        self.store = Store(os.path.join(self.data, "control.db")); self.audit = Audit(os.path.join(self.data, "control_audit.log"))
        self.worker = Worker(self.store, self.data, self.audit, workers=workers, autostart=autostart)
        from .chat import ChatService
        self.chat = ChatService(self.store, self.worker, self.audit)
        self.secure_cookie, self.t0 = secure_cookie, time.time()
        dis = self.store.get("disabled_tools", [])
        if dis: os.environ["CYBERSWARM_DISABLE_TOOLS"] = ",".join(dis)
    # ----- helpers -----
    def visible(self, user, cid): return user["clients"] is None or cid in user["clients"]
    def job(self, user, jid):
        j = self.store.q("SELECT * FROM jobs WHERE id=?", (int(jid),), one=True)
        if not j or not self.visible(user, j["client_id"]): raise HTTPError(404, "tarefa não encontrada")
        return j
    def job_db(self, j):
        p = os.path.join(job_dir(self.data, j["client_id"], j["id"]), "cyberswarm.db")
        return DB(p) if os.path.exists(p) else None
    def core_run(self, j, db):
        s = json.loads(j["summary"] or "{}")
        if s.get("core_run"): return s["core_run"]
        r = db.c.execute("SELECT id FROM runs ORDER BY id DESC LIMIT 1").fetchone() if db else None
        return r[0] if r else None
    def findings(self, j):
        db = self.job_db(j)
        if not db: return []
        rid = self.core_run(j, db); return db.findings(rid) if rid else []
A = App
# ---------------- auth ----------------
@route("POST", "/api/login", "public")
def login(app, h, user, m, body):
    u, p = str(body.get("username", ""))[:64], str(body.get("password", ""))[:256]
    st, tok, csrf = app.store.login(u, p, h.client_address[0])
    if st == "locked":
        app.audit.log("login_locked", username=u, ip=h.client_address[0]); raise HTTPError(429, "muitas tentativas; aguarde 15 minutos")
    if st != "ok":
        app.audit.log("login_failed", username=u, ip=h.client_address[0]); raise HTTPError(401, "usuário ou senha inválidos")
    app.audit.log("login_ok", username=u, ip=h.client_address[0])
    h.set_cookie = f"cs_session={tok}; HttpOnly; SameSite=Strict; Path=/; Max-Age=43200" + ("; Secure" if app.secure_cookie else "")
    s = app.store.session(tok); return {"username": s["username"], "role": s["role"], "csrf": csrf}
@route("POST", "/api/logout")
def logout(app, h, user, m, body):
    app.store.logout(h.cookie("cs_session")); app.audit.log("logout", username=user["username"])
    h.set_cookie = "cs_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0"; return {"ok": True}
@route("GET", "/api/me")
def me(app, h, user, m, body): return {"username": user["username"], "role": user["role"], "csrf": user["csrf"], "clients": user["clients"]}
@route("GET", "/api/users", "owner")
def users(app, h, user, m, body): return [{k: v for k, v in u.items() if k != "pw"} for u in app.store.users()]
@route("POST", "/api/users", "owner")
def add_user(app, h, user, m, body):
    try: uid = app.store.add_user(str(body["username"])[:64], str(body["password"]), body.get("role", "viewer"), body.get("clients"))
    except (KeyError, ValueError) as e: raise HTTPError(400, str(e))
    except Exception: raise HTTPError(409, "usuário já existe")
    app.audit.log("user_created", by=user["username"], username=body["username"], role=body.get("role", "viewer")); return {"id": uid}
# ---------------- dashboard / monitor ----------------
@route("GET", "/api/dashboard")
def dashboard(app, h, user, m, body):
    jobs = [j for j in app.store.q("SELECT * FROM jobs ORDER BY id DESC") if app.visible(user, j["client_id"])]
    sev = {}; conf = 0
    for j in jobs[:50]:
        if j["status"] != "concluida": continue
        for f in app.findings(j):
            sev[f["severity"]] = sev.get(f["severity"], 0) + 1; conf += f["status"] == "confirmado"
    st = {}
    for j in jobs: st[j["status"]] = st.get(j["status"], 0) + 1
    pend = [a for a in app.store.q("SELECT * FROM approvals WHERE status='pendente'") if app.visible(user, a["client_id"])]
    cl = [c for c in app.store.q("SELECT id FROM clients") if app.visible(user, c["id"])]
    return {"jobs_por_status": st, "aprovacoes_pendentes": len(pend), "clientes": len(cl), "achados_por_severidade": sev, "confirmados": conf,
            "fila": app.worker.q.qsize(), "ultimas": [jsum(j) for j in jobs[:8]]}
def jsum(j):
    s = json.loads(j["summary"] or "{}")
    return {"id": j["id"], "client_id": j["client_id"], "kind": j["kind"], "goal": j["goal"], "status": j["status"], "created_by": j["created_by"],
            "created": j["created"], "started": j["started"], "finished": j["finished"], "error": j["error"],
            "findings": s.get("findings", (s.get("metricas") or {}).get("achados")), "confirmed": s.get("confirmed"),
            "progress": j.get("progress"), "attempts": j.get("attempts"), "paused": j.get("paused")}
@route("GET", "/api/ping", "public")
def ping(app, h, user, m, body):
    """Keep-alive público (sem dados sensíveis) — útil em free tiers que dormem."""
    return {"ok": True, "ts": int(time.time()), "uptime_s": round(time.time() - app.t0)}
@route("GET", "/api/monitor")
def monitor(app, h, user, m, body):
    du = shutil.disk_usage(app.data); alive = sum(t.is_alive() for t in app.worker.threads)
    ok, line = audit_verify(app.audit.path) if os.path.exists(app.audit.path) else (True, 0)
    return {"uptime_s": round(time.time() - app.t0), "workers_vivos": alive, "workers_total": len(app.worker.threads), "fila": app.worker.q.qsize(),
            "disco_livre_gb": round(du.free / 1e9, 1), "db_kb": round(os.path.getsize(os.path.join(app.data, "control.db")) / 1024),
            "auditoria_integra": ok, "auditoria_linha_quebrada": line}
@route("GET", "/api/audit")
def audit_log(app, h, user, m, body):
    n = min(int(h.qs.get("limit", ["200"])[0]), 1000); lines = []
    if os.path.exists(app.audit.path):
        with open(app.audit.path) as f: lines = [json.loads(x) for x in f if x.strip()][-n:]
    if user["clients"] is not None: lines = [x for x in lines if not x.get("client") or x.get("client") in user["clients"]]
    ok, line = audit_verify(app.audit.path) if os.path.exists(app.audit.path) else (True, 0)
    return {"integra": ok, "linha_quebrada": line, "eventos": list(reversed(lines))}
# ---------------- jobs (Hacker AI) ----------------
@route("GET", "/api/jobs")
def jobs(app, h, user, m, body):
    c = h.qs.get("client", [None])[0]
    return [jsum(j) for j in app.store.q("SELECT * FROM jobs ORDER BY id DESC LIMIT 300") if app.visible(user, j["client_id"]) and (not c or j["client_id"] == c)]
@route("POST", "/api/jobs", "owner")
def create_job(app, h, user, m, body):
    cid = str(body.get("client_id") or LAB)
    try: jid = app.worker.create(user, str(body.get("kind", "hacker")), cid, body.get("goal"), body.get("target"), body.get("lab"))
    except Exception as e:
        app.audit.log("job_rejected", by=user["username"], client=cid, reason=str(e)[:200]); raise HTTPError(400, f"recusado: {e}")
    return {"id": jid, "status": app.store.q("SELECT status FROM jobs WHERE id=?", (jid,), one=True)["status"]}
@route("GET", r"/api/jobs/(\d+)")
def job_detail(app, h, user, m, body):
    j = app.job(user, m[1]); db = app.job_db(j); rid = app.core_run(j, db) if db else None
    tasks = db.tasks(rid) if rid else []
    d = job_dir(app.data, j["client_id"], j["id"]); msgs = []
    s = json.loads(j["summary"] or "{}")
    if s.get("hacker_run") and os.path.exists(os.path.join(d, f"hacker-{s['hacker_run']}.json")):
        bus = json.load(open(os.path.join(d, f"hacker-{s['hacker_run']}.json"))).get("bus", [])
        msgs = [{"type": b.get("type"), "sender": b.get("sender"), "payload": b.get("payload")} for b in bus[-150:]]
    elif os.path.exists(os.path.join(d, "hacker_memory.db")):
        import sqlite3
        try:
            c = sqlite3.connect(os.path.join(d, "hacker_memory.db"))
            msgs = [{"type": r[0], "sender": r[1], "payload": json.loads(r[2])} for r in c.execute("SELECT type,sender,payload FROM messages ORDER BY id DESC LIMIT 60")][::-1]
        except Exception: msgs = []
    aps = app.store.q("SELECT id,op,target,status,decided_by,reason,detail FROM approvals WHERE job_id=?", (j["id"],))
    js = jsum(j); js["progress"] = j.get("progress"); js["paused"] = j.get("paused"); js["attempts"] = j.get("attempts")
    return {"job": js, "summary": s, "tasks": [{k: t[k] for k in ("agent", "target", "status", "error")} for t in tasks], "mensagens": msgs,
            "aprovacoes": aps, "arquivos": files(app, j)}
def files(app, j):
    d = job_dir(app.data, j["client_id"], j["id"])
    if not os.path.isdir(d): return []
    return sorted(f for f in os.listdir(d) if re.match(r"^report-[\w-]+\.(pdf|html|md|json)$", f))
@route("GET", r"/api/jobs/(\d+)/findings")
def job_findings(app, h, user, m, body):
    j = app.job(user, m[1]); out = []
    for f in app.findings(j):
        f = dict(f)
        for k in ("proof", "refs"):
            try: f[k] = json.loads(f[k]) if isinstance(f[k], str) else f[k]
            except Exception: pass
        if isinstance(f.get("proof"), dict): f["proof"].pop("abs", None)   # não expõe caminho absoluto do servidor
        out.append(f)
    return out
@route("GET", r"/api/jobs/(\d+)/files/([\w.-]+)")
def job_file(app, h, user, m, body):
    j = app.job(user, m[1]); name = m[2]
    if name not in files(app, j): raise HTTPError(404, "arquivo não encontrado")
    p = os.path.join(job_dir(app.data, j["client_id"], j["id"]), name)
    app.audit.log("report_download", by=user["username"], job=j["id"], client=j["client_id"], file=name)
    return ("file", p, h.qs.get("dl", ["0"])[0] == "1")
@route("GET", "/api/compare")
def compare(app, h, user, m, body):
    try: a, b = app.job(user, h.qs["a"][0]), app.job(user, h.qs["b"][0])
    except (KeyError, ValueError): raise HTTPError(400, "informe a e b")
    if a["client_id"] != b["client_id"]: raise HTTPError(400, "só é possível comparar auditorias do mesmo cliente")
    class Shim:
        def findings(self, which): return app.findings(a if which == "a" else b)
    r = compare_runs(Shim(), "a", "b")
    return {k: [{x: f[x] for x in ("check_id", "title", "severity", "status", "target")} for f in v] for k, v in r.items()}
# ---------------- approvals ----------------
@route("GET", "/api/approvals")
def approvals(app, h, user, m, body):
    return [a for a in app.store.q("SELECT * FROM approvals ORDER BY id DESC LIMIT 300") if app.visible(user, a["client_id"])]
@route("POST", r"/api/approvals/(\d+)", "owner")
def decide(app, h, user, m, body):
    if body.get("decision") not in ("approve", "deny"): raise HTTPError(400, "decision deve ser approve ou deny")
    try: st = app.worker.decide(user, int(m[1]), body["decision"] == "approve", str(body.get("reason", "")))
    except KeyError as e: raise HTTPError(404, str(e))
    except ValueError as e: raise HTTPError(400, str(e))
    return {"status": st}
# ---------------- clients / scopes ----------------
CF = ("name", "authorization_ref", "authorized_by", "valid_from", "valid_until")
def clean_client(body, cid=None):
    from ..scope import FORBIDDEN_KEYS
    bad = [k for k in body if k.lower() in FORBIDDEN_KEYS]
    if bad: raise HTTPError(400, f"não guarde credenciais aqui (campos: {bad})")
    for k in CF:
        if not str(body.get(k, "")).strip(): raise HTTPError(400, f"campo obrigatório: {k}")
    try:
        if datetime.date.fromisoformat(body["valid_from"]) > datetime.date.fromisoformat(body["valid_until"]): raise HTTPError(400, "validade invertida")
    except ValueError: raise HTTPError(400, "datas no formato AAAA-MM-DD")
    hosts = [x.strip().lower() for x in body.get("hosts", []) if str(x).strip()]
    if not hosts: raise HTTPError(400, "informe pelo menos um host autorizado")
    for x in hosts:
        if not re.match(r"^[a-z0-9.-]+(:\d+)?$", x) or x.startswith("*"): raise HTTPError(400, f"host inválido (sem curingas): {x}")
    return [str(body[k]).strip()[:300] for k in CF] + [str(body.get("contact", ""))[:200], json.dumps(hosts), json.dumps([]), str(body.get("notes", ""))[:1000]]
@route("GET", "/api/clients")
def clients(app, h, user, m, body):
    out = []
    for c in app.store.q("SELECT * FROM clients ORDER BY id"):
        if not app.visible(user, c["id"]): continue
        c["hosts"] = json.loads(c["hosts"]); today = datetime.date.today().isoformat()
        c["vigente"] = c["valid_from"] <= today <= c["valid_until"]; out.append(c)
    return out
@route("POST", "/api/clients", "owner")
def add_client(app, h, user, m, body):
    cid = str(body.get("id", "")).strip().lower()
    if not SAFE_ID.match(cid) or cid == LAB: raise HTTPError(400, "id: minúsculas, números e hífen (2–41)")
    v = clean_client(body)
    if app.store.q("SELECT id FROM clients WHERE id=?", (cid,), one=True): raise HTTPError(409, "cliente já existe")
    app.store.x("INSERT INTO clients(id,name,authorization_ref,authorized_by,valid_from,valid_until,contact,hosts,paths,notes,created,updated) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)", [cid] + v + [time.time(), time.time()])
    app.audit.log("client_created", by=user["username"], client=cid, authorization_ref=v[1], hosts=json.loads(v[7])); return {"id": cid}
@route("PUT", r"/api/clients/([a-z0-9-]+)", "owner")
def upd_client(app, h, user, m, body):
    if not app.store.q("SELECT id FROM clients WHERE id=?", (m[1],), one=True): raise HTTPError(404, "cliente não encontrado")
    v = clean_client(body)
    app.store.x("UPDATE clients SET name=?,authorization_ref=?,authorized_by=?,valid_from=?,valid_until=?,contact=?,hosts=?,paths=?,notes=?,updated=? WHERE id=?", v + [time.time(), m[1]])
    app.audit.log("client_updated", by=user["username"], client=m[1], authorization_ref=v[1], hosts=json.loads(v[7])); return {"id": m[1]}
@route("DELETE", r"/api/clients/([a-z0-9-]+)", "owner")
def del_client(app, h, user, m, body):
    if app.store.q("SELECT id FROM jobs WHERE client_id=? LIMIT 1", (m[1],), one=True): raise HTTPError(409, "cliente tem auditorias; mantenha o registro (trilha de auditoria)")
    app.store.x("DELETE FROM clients WHERE id=?", (m[1],)); app.audit.log("client_deleted", by=user["username"], client=m[1]); return {"ok": True}
# ---------------- tools / modules ----------------
@route("GET", "/api/tools")
def tools(app, h, user, m, body):
    from ..registry import load_all
    from ..tools import which
    from ..extval.labs import LABS, status
    dis = app.store.get("disabled_tools", [])
    ag = load_all()
    return {"agentes": [{"nome": n, "descricao": (c.__doc__ or "").strip().split("\n")[0][:140]} for n, c in sorted(ag.items())],
            "ferramentas": [{"nome": t, "instalada": bool(which(t)) or (t in dis and bool(__import__("shutil").which(t))), "desativada": t in dis} for t in EXT_TOOLS],
            "laboratorios": [{"nome": n, "estado": status(n), "descricao": l.get("name", ""), "motivo": l.get("reason")} for n, l in LABS.items()]}
@route("POST", "/api/tools", "owner")
def set_tools(app, h, user, m, body):
    dis = [t for t in body.get("disabled", []) if t in EXT_TOOLS]
    app.store.set("disabled_tools", dis)
    if dis: os.environ["CYBERSWARM_DISABLE_TOOLS"] = ",".join(dis)
    else: os.environ.pop("CYBERSWARM_DISABLE_TOOLS", None)
    app.audit.log("tools_changed", by=user["username"], disabled=dis); return {"disabled": dis}
# ---------------- finance (manual) ----------------
@route("GET", "/api/finance")
def finance(app, h, user, m, body):
    rows = [r for r in app.store.q("SELECT * FROM finance ORDER BY date DESC, id DESC") if not r["client_id"] or app.visible(user, r["client_id"])]
    tot = {k: sum(r["amount_cents"] for r in rows if r["kind"] == k) for k in ("receita", "despesa", "proposta")}
    return {"lancamentos": rows, "totais_centavos": tot, "saldo_centavos": tot["receita"] - tot["despesa"], "fonte": "somente lançamentos manuais"}
@route("POST", "/api/finance", "owner")
def add_fin(app, h, user, m, body):
    try:
        datetime.date.fromisoformat(str(body["date"])); amt = int(round(float(body["amount"]) * 100)); kind = body["kind"]
        assert kind in ("receita", "despesa", "proposta") and amt >= 0 and str(body.get("description", "")).strip()
    except Exception: raise HTTPError(400, "dados inválidos (data AAAA-MM-DD, tipo, valor >= 0, descrição)")
    cid = body.get("client_id") or None
    if cid and not app.store.q("SELECT id FROM clients WHERE id=?", (cid,), one=True): raise HTTPError(400, "cliente inexistente")
    fid = app.store.x("INSERT INTO finance(date,kind,client_id,description,amount_cents,status,created_by,created) VALUES(?,?,?,?,?,?,?,?)",
                      (body["date"], kind, cid, str(body["description"])[:300], amt, str(body.get("status", ""))[:40], user["username"], time.time()))
    app.audit.log("finance_added", by=user["username"], id=fid, kind=kind, client=cid); return {"id": fid}
@route("DELETE", r"/api/finance/(\d+)", "owner")
def del_fin(app, h, user, m, body):
    app.store.x("DELETE FROM finance WHERE id=?", (int(m[1]),)); app.audit.log("finance_deleted", by=user["username"], id=int(m[1])); return {"ok": True}

# ---------------- chat / settings / job control ----------------
@route("GET", "/api/chat/threads")
def chat_threads(app, h, user, m, body):
    return app.chat.threads(user, h.qs.get("client", [None])[0])
@route("POST", "/api/chat/threads", "owner")
def chat_new(app, h, user, m, body):
    try: tid = app.chat.ensure_thread(user, str(body.get("client_id") or LAB), body.get("title"))
    except (ValueError, PermissionError) as e: raise HTTPError(400, str(e))
    return {"id": tid}
@route("GET", r"/api/chat/threads/(\d+)")
def chat_msgs(app, h, user, m, body):
    try: msgs, th = app.chat.messages(user, int(m[1]))
    except KeyError: raise HTTPError(404, "conversa não encontrada")
    return {"thread": th, "messages": msgs}
@route("POST", r"/api/chat/threads/(\d+)/messages", "owner")
def chat_send(app, h, user, m, body):
    try: return app.chat.handle(user, int(m[1]), str(body.get("content") or body.get("text") or ""))
    except KeyError: raise HTTPError(404, "conversa não encontrada")
    except ValueError as e: raise HTTPError(400, str(e))
@route("GET", "/api/settings")
def get_settings(app, h, user, m, body):
    cfg = app.store.get("ai_provider", {"mode": "none", "fallback": ["none"]}) or {}
    # nunca devolve a chave
    safe = {k: v for k, v in cfg.items() if k != "api_key_enc"}
    safe["has_api_key"] = bool(cfg.get("api_key_enc") or __import__("os").environ.get("CYBERSWARM_AI_KEY"))
    safe["deterministic"] = bool(app.store.get("deterministic", False))
    from ..providers import get_provider
    p = get_provider(cfg, deterministic=safe["deterministic"])
    safe["provider_ativo"] = p.name; safe["provider_disponivel"] = p.available()
    return safe
@route("POST", "/api/settings", "owner")
def set_settings(app, h, user, m, body):
    from ..providers import encrypt_secret
    cfg = app.store.get("ai_provider", {"mode": "none", "fallback": ["none"]}) or {}
    if "mode" in body: cfg["mode"] = str(body["mode"])[:20]
    if "base_url" in body: cfg["base_url"] = str(body["base_url"] or "")[:200]
    if "model" in body: cfg["model"] = str(body["model"] or "")[:80]
    if "fallback" in body and isinstance(body["fallback"], list): cfg["fallback"] = [str(x)[:20] for x in body["fallback"][:5]]
    if body.get("api_key"):
        # só aceita https:// para openai-compat
        cfg["api_key_enc"] = encrypt_secret(str(body["api_key"])[:200])
    if body.get("clear_api_key"): cfg.pop("api_key_enc", None)
    if "deterministic" in body: app.store.set("deterministic", bool(body["deterministic"]))
    app.store.set("ai_provider", cfg)
    app.audit.log("settings_changed", by=user["username"], mode=cfg.get("mode"), deterministic=bool(app.store.get("deterministic", False)))
    return get_settings(app, h, user, m, {})
@route("POST", r"/api/jobs/(\d+)/pause", "owner")
def job_pause(app, h, user, m, body):
    try: return {"status": app.worker.pause(user, int(m[1]))}
    except KeyError: raise HTTPError(404, "tarefa não encontrada")
    except ValueError as e: raise HTTPError(400, str(e))
@route("POST", r"/api/jobs/(\d+)/cancel", "owner")
def job_cancel(app, h, user, m, body):
    try: return {"status": app.worker.cancel(user, int(m[1]))}
    except KeyError: raise HTTPError(404, "tarefa não encontrada")
    except ValueError as e: raise HTTPError(400, str(e))
@route("POST", r"/api/jobs/(\d+)/resume", "owner")
def job_resume(app, h, user, m, body):
    try: return {"status": app.worker.resume_paused(user, int(m[1]))}
    except ValueError as e: raise HTTPError(400, str(e))

# ---------------- HTTP ----------------
STATIC_MAP = {"/": "index.html", "/manifest.json": "manifest.json", "/sw.js": "sw.js", "/app.js": "app.js", "/style.css": "style.css",
              "/icon-192.png": "icon-192.png", "/icon-512.png": "icon-512.png", "/icon-maskable-512.png": "icon-maskable-512.png"}
def make_handler(app):
    class H(BaseHTTPRequestHandler):
        server_version = "CyberSwarmControl/1.0"; sys_version = ""
        def log_message(self, *a): pass
        def cookie(self, name):
            c = SimpleCookie(self.headers.get("Cookie", "")); return c[name].value if name in c else None
        def hdrs(self, code, ctype, length, extra=()):
            self.send_response(code); self.send_header("Content-Type", ctype); self.send_header("Content-Length", str(length))
            for k, v in (("Content-Security-Policy", CSP), ("X-Content-Type-Options", "nosniff"), ("Referrer-Policy", "no-referrer"),
                         ("X-Frame-Options", "SAMEORIGIN"), ("Permissions-Policy", "camera=(), microphone=(), geolocation=()"), ("Cross-Origin-Opener-Policy", "same-origin")): self.send_header(k, v)
            for k, v in extra: self.send_header(k, v)
            self.end_headers()
        def js(self, code, obj):
            b = json.dumps(obj, ensure_ascii=False, default=str).encode(); ex = [("Cache-Control", "no-store")]
            if getattr(self, "set_cookie", None): ex.append(("Set-Cookie", self.set_cookie))
            self.hdrs(code, "application/json; charset=utf-8", len(b), ex); self.wfile.write(b)
        def handle_any(self, method):
            u = urlparse(self.path); path = u.path; self.qs = parse_qs(u.query); self.set_cookie = None
            if method == "GET" and path in STATIC_MAP:
                p = os.path.join(STATIC, STATIC_MAP[path]); b = open(p, "rb").read()
                ct = {"manifest.json": "application/manifest+json"}.get(STATIC_MAP[path]) or mimetypes.guess_type(p)[0] or "application/octet-stream"
                if ct.startswith("text/") or ct.endswith("javascript"): ct += "; charset=utf-8"
                ex = [("Cache-Control", "no-cache")] + ([("Service-Worker-Allowed", "/")] if path == "/sw.js" else [])
                return self.hdrs(200, ct, len(b), ex) or self.wfile.write(b)
            for meth, rx, fn, role in ROUTES:
                mm = rx.match(path)
                if not mm or meth != method: continue
                try:
                    user = None
                    if role != "public":
                        user = app.store.session(self.cookie("cs_session"))
                        if not user: raise HTTPError(401, "não autenticado")
                        if role == "owner" and user["role"] != "owner": raise HTTPError(403, "permissão insuficiente (somente owner)")
                    body = {}
                    if method != "GET":
                        org = self.headers.get("Origin")
                        if org and urlparse(org).netloc != self.headers.get("Host"): raise HTTPError(403, "origem não permitida")
                        if role != "public" and not hmac.compare_digest(self.headers.get("X-CSRF-Token", ""), user["csrf"]): raise HTTPError(403, "CSRF inválido")
                        n = int(self.headers.get("Content-Length") or 0)
                        if n > MAX_BODY: raise HTTPError(413, "corpo grande demais")
                        if n:
                            if not (self.headers.get("Content-Type", "").startswith("application/json")): raise HTTPError(415, "use application/json")
                            try: body = json.loads(self.rfile.read(n))
                            except Exception: raise HTTPError(400, "JSON inválido")
                            if not isinstance(body, dict): raise HTTPError(400, "JSON deve ser objeto")
                    r = fn(app, self, user, mm, body)
                    if isinstance(r, tuple) and r[0] == "file":
                        _, p, dl = r; b = open(p, "rb").read(); ct = mimetypes.guess_type(p)[0] or "application/octet-stream"
                        disp = ("attachment" if dl else "inline") + f'; filename="{os.path.basename(p)}"'
                        return self.hdrs(200, ct, len(b), [("Content-Disposition", disp), ("Cache-Control", "no-store")]) or self.wfile.write(b)
                    return self.js(200, r)
                except HTTPError as e: return self.js(e.code, {"erro": e.msg})
                except Exception as e:
                    app.audit.log("api_error", path=path, error=repr(e)[:200]); return self.js(500, {"erro": "erro interno"})
            if path.startswith("/api/"): return self.js(404, {"erro": "rota inexistente"})
            self.js(404, {"erro": "não encontrado"})
        def do_GET(self): self.handle_any("GET")
        def do_POST(self): self.handle_any("POST")
        def do_PUT(self): self.handle_any("PUT")
        def do_DELETE(self): self.handle_any("DELETE")
    return H
def serve(data, host="127.0.0.1", port=8770, allow_lan=False, workers=2, autostart=True, block=True, secure_cookie=False, tls=False, cert=None, key=None):
    if host not in LOOPBACK and not allow_lan: raise ValueError("bind fora de 127.0.0.1 exige --allow-lan (veja docs/CONTROL.md)")
    if tls or cert: secure_cookie = True
    app = App(data, workers=workers, autostart=autostart, secure_cookie=secure_cookie)
    srv = ThreadingHTTPServer((host, port), make_handler(app)); srv.app = app; srv.daemon_threads = True
    scheme = "http"
    if tls or cert:
        from .tlsutil import ensure_self_signed, ssl_context
        c, k = (cert, key) if cert and key else ensure_self_signed(os.path.join(app.data, "tls"), host=host)
        srv.socket = ssl_context(c, k).wrap_socket(srv.socket, server_side=True); scheme = "https"
    app.audit.log("control_start", host=host, port=port, tls=scheme == "https")
    if host not in LOOPBACK: print("ATENÇÃO: acessível na rede local. Use só em rede confiável; prefira túnel HTTPS (docs/CONTROL.md).")
    print(f"CyberSwarm Control em {scheme}://{host}:{port}/  (dados: {app.data})")
    if not block:
        import threading; threading.Thread(target=srv.serve_forever, daemon=True).start(); return srv
    try: srv.serve_forever()
    except KeyboardInterrupt: pass
    return 0
