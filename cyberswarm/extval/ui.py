"""Lightweight mobile-friendly web UI (stdlib http.server). Binds ONLY 127.0.0.1. Token auth (cookie after login).
Can only start scans of the registered local labs (no free-form targets) — client audits stay in the CLI with approvals."""
import hashlib, hmac, html, json, os, secrets, threading, time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse
from .labs import LABS, status
E = html.escape
CSS = """*{box-sizing:border-box}body{font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif;margin:0;background:#0f172a;color:#e2e8f0}
header{background:#111827;padding:14px 16px;border-bottom:1px solid #1f2937}h1{font-size:18px;margin:0}small{color:#94a3b8}
main{padding:12px;max-width:960px;margin:auto}.card{background:#1e293b;border-radius:12px;padding:14px;margin:10px 0}
.row{display:flex;justify-content:space-between;align-items:center;gap:8px;flex-wrap:wrap}.pill{padding:2px 10px;border-radius:99px;font-size:12px}
.up{background:#166534}.down{background:#7f1d1d}.nao_executavel{background:#78350f}button,.btn{background:#2563eb;color:#fff;border:0;border-radius:10px;padding:10px 14px;font-size:15px;text-decoration:none;display:inline-block}
input{padding:10px;border-radius:10px;border:1px solid #334155;background:#0f172a;color:#e2e8f0;width:100%;font-size:16px}
table{width:100%;border-collapse:collapse;font-size:13px}td,th{border-bottom:1px solid #334155;padding:6px;text-align:left;vertical-align:top}
.k{font-size:24px;font-weight:700}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));gap:8px}a{color:#93c5fd}
.sev-critical,.sev-high{color:#fca5a5}.sev-medium{color:#fcd34d}"""
def page(title, body):
    return (f"<!doctype html><html lang='pt-BR'><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'>"
            f"<title>{E(title)}</title><style>{CSS}</style></head><body><header><h1>CyberSwarm · Hacker AI 1.1</h1><small>defensivo · somente 127.0.0.1</small></header><main>{body}</main></body></html>").encode()
class State:
    def __init__(self, out, token):
        self.out, self.token, self.jobs, self.lock = out, token, {}, threading.Lock()
        self.csrf = hashlib.sha256(("csrf" + token).encode()).hexdigest()[:32]
    def runs(self):
        rs = []
        for d in sorted(os.listdir(self.out)) if os.path.isdir(self.out) else []:
            for f in os.listdir(os.path.join(self.out, d)) if os.path.isdir(os.path.join(self.out, d)) else []:
                if f.startswith("extval_") and f.endswith(".json"): rs.append((d, os.path.join(self.out, d, f)))
        return rs
def make_handler(st):
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a): pass
        def send(self, code, body, ctype="text/html; charset=utf-8", extra=None):
            self.send_response(code)
            for k, v in {"Content-Type": ctype, "X-Frame-Options": "DENY", "X-Content-Type-Options": "nosniff", "Referrer-Policy": "no-referrer",
                         "Content-Security-Policy": "default-src 'self'; style-src 'unsafe-inline'; img-src 'self' data:", "Cache-Control": "no-store", **(extra or {})}.items():
                self.send_header(k, v)
            self.end_headers(); self.wfile.write(body)
        def authed(self):
            c = self.headers.get("Cookie", ""); b = self.headers.get("Authorization", "")
            tok = next((x.split("=", 1)[1] for x in c.split("; ") if x.startswith("cs_token=")), "") or (b[7:] if b.startswith("Bearer ") else "")
            return bool(tok) and hmac.compare_digest(tok, st.token)
        def form(self):
            n = int(self.headers.get("Content-Length") or 0)
            if n > 10000: return {}
            return {k: v[0] for k, v in parse_qs(self.rfile.read(n).decode()).items()}
        def login_page(self, msg=""):
            self.send(401, page("Entrar", f"<div class='card'><form method='post' action='/login'><p>Token de acesso (impresso ao iniciar a UI):</p>"
                                          f"<input name='token' type='password' autocomplete='off'><p><button>Entrar</button></p><p>{E(msg)}</p></form></div>"))
        def do_GET(self):
            u = urlparse(self.path)
            if not self.authed(): return self.login_page()
            if u.path == "/": return self.dashboard()
            if u.path == "/api/runs":
                return self.send(200, json.dumps([json.load(open(p))["resultado"] for _, p in st.runs()], default=str).encode(), "application/json")
            if u.path.startswith("/run/"): return self.run_page(u.path[5:])
            if u.path in ("/report.html", "/report.pdf"):
                p = os.path.join(st.out, "report", u.path[1:])
                if os.path.exists(p): return self.send(200, open(p, "rb").read(), "application/pdf" if p.endswith(".pdf") else "text/html; charset=utf-8")
            self.send(404, page("404", "<div class='card'>Não encontrado</div>"))
        def do_POST(self):
            u = urlparse(self.path); f = self.form()
            if u.path == "/login":
                if hmac.compare_digest(f.get("token", ""), st.token):
                    return self.send(303, b"", extra={"Location": "/", "Set-Cookie": f"cs_token={st.token}; HttpOnly; SameSite=Strict; Path=/"})
                time.sleep(0.5); return self.login_page("Token inválido")
            if not self.authed(): return self.login_page()
            if u.path == "/scan":
                if not hmac.compare_digest(f.get("csrf", ""), st.csrf): return self.send(403, page("403", "<div class='card'>CSRF inválido</div>"))
                lab = f.get("lab", "")
                if lab not in LABS or LABS[lab]["kind"] == "skip": return self.send(400, page("400", "<div class='card'>Laboratório desconhecido</div>"))
                self.start(lab, f.get("mode", "1.1") if f.get("mode") in ("1.0", "1.1") else "1.1", f.get("nuclei") == "on")
                return self.send(303, b"", extra={"Location": "/"})
            self.send(404, b"")
        def start(self, lab, mode, nuclei):
            key = f"{lab}-{mode}"
            with st.lock:
                if st.jobs.get(key, {}).get("estado") == "executando": return
                st.jobs[key] = {"estado": "executando", "inicio": time.strftime("%H:%M:%S")}
            def work():
                from .runner import run_lab
                try:
                    r, _ = run_lab(lab, os.path.join(st.out, key), mode=mode, use_nuclei=nuclei); st.jobs[key] = {"estado": "concluído" if r.get("metricas") else "erro: " + str(r.get("erro"))}
                except Exception as e: st.jobs[key] = {"estado": f"erro: {e!r}"[:200]}
            threading.Thread(target=work, daemon=True).start()
        def dashboard(self):
            cards = []
            for n, l in LABS.items():
                s = status(n); job = st.jobs.get(f"{n}-1.1", {}).get("estado", "")
                btn = "" if l["kind"] == "skip" else (f"<form method='post' action='/scan' class='row'><input type='hidden' name='csrf' value='{st.csrf}'><input type='hidden' name='lab' value='{E(n)}'>"
                      f"<label><input type='checkbox' name='nuclei' style='width:auto'> nuclei</label><button>Iniciar varredura</button></form>")
                cards.append(f"<div class='card'><div class='row'><b>{E(n)}</b><span class='pill {s}'>{E(s)}</span></div><small>{E(l['project'])}</small>"
                             f"<p><small>{E(l.get('reason',''))}</small></p><p>{E(job)}</p>{btn}</div>")
            runs = "".join(f"<tr><td><a href='/run/{E(d)}'>{E(d)}</a></td></tr>" for d, _ in st.runs()) or "<tr><td>nenhuma execução</td></tr>"
            links = "<a class='btn' href='/report.html'>Relatório HTML</a> <a class='btn' href='/report.pdf'>PDF</a>" if os.path.exists(os.path.join(st.out, "report", "report.html")) else ""
            self.send(200, page("Painel", "<h2>Laboratórios</h2>" + "".join(cards) + f"<h2>Execuções</h2><div class='card'><table>{runs}</table></div><p>{links}</p>"))
        def run_page(self, name):
            p = dict(st.runs()).get(name)
            if not p: return self.send(404, page("404", "<div class='card'>Execução não encontrada</div>"))
            d = json.load(open(p)); r = d["resultado"]; m = r.get("metricas", {})
            k = lambda t, v: f"<div class='card'><div class='k'>{E(str(v))}</div><small>{E(t)}</small></div>"
            grid = "<div class='grid'>" + k("itens oficiais", m.get("itens_oficiais")) + k("detectados", m.get("detectados")) + k("revocação", f"{(m.get('revocacao') or 0):.1%}") + \
                   k("achados", m.get("achados")) + k("não reproduzidos", m.get("nao_reproduzidos")) + k("tempo (s)", r.get("segundos")) + "</div>"
            rows = "".join(f"<tr><td class='sev-{E(f['severity'])}'>{E(f['severity'])}</td><td>{E(f['status'])}</td><td>{E(f['title'][:90])}</td><td><small>{E(str(f['target'])[:60])}</small></td></tr>" for f in d["achados"])
            self.send(200, page(name, f"<p><a href='/'>← voltar</a></p><h2>{E(name)}</h2>{grid}<div class='card'><table><tr><th>grav.</th><th>status</th><th>achado</th><th>alvo</th></tr>{rows}</table></div>"))
    return H
def serve(out, port=8765, token=None, block=True):
    os.makedirs(out, exist_ok=True)
    token = token or os.environ.get("CYBERSWARM_UI_TOKEN") or secrets.token_urlsafe(18)
    tp = os.path.join(out, "ui_token"); open(tp, "w").write(token); os.chmod(tp, 0o600)
    srv = ThreadingHTTPServer(("127.0.0.1", port), make_handler(State(out, token)))
    if not block:
        threading.Thread(target=srv.serve_forever, daemon=True).start(); return srv
    print(f"UI em http://127.0.0.1:{port}/  (token salvo em {tp})"); srv.serve_forever()
