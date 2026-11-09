"""Persistência SQLite do Control: usuários (scrypt), sessões (hash do token), clientes/escopos, tarefas, aprovações, lançamentos financeiros."""
import hashlib, hmac, json, os, secrets, sqlite3, threading, time
SCHEMA = """
CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL, role TEXT NOT NULL CHECK(role IN ('owner','viewer')),
  pw TEXT NOT NULL, clients TEXT, created REAL);
CREATE TABLE IF NOT EXISTS sessions(th TEXT PRIMARY KEY, user_id INT NOT NULL, csrf TEXT NOT NULL, expires REAL NOT NULL, ip TEXT);
CREATE TABLE IF NOT EXISTS login_fail(id INTEGER PRIMARY KEY, ip TEXT, username TEXT, ts REAL);
CREATE TABLE IF NOT EXISTS clients(id TEXT PRIMARY KEY, name TEXT NOT NULL, authorization_ref TEXT NOT NULL, authorized_by TEXT NOT NULL,
  contact TEXT, valid_from TEXT NOT NULL, valid_until TEXT NOT NULL, hosts TEXT NOT NULL, paths TEXT NOT NULL, notes TEXT, created REAL, updated REAL);
CREATE TABLE IF NOT EXISTS jobs(id INTEGER PRIMARY KEY, client_id TEXT NOT NULL, kind TEXT NOT NULL, goal TEXT, targets TEXT, status TEXT NOT NULL,
  created_by TEXT, created REAL, started REAL, finished REAL, approval_token TEXT, summary TEXT, error TEXT);
CREATE TABLE IF NOT EXISTS approvals(id INTEGER PRIMARY KEY, job_id INT NOT NULL, op TEXT NOT NULL, target TEXT NOT NULL, client_id TEXT NOT NULL,
  detail TEXT, status TEXT NOT NULL DEFAULT 'pendente', requested_by TEXT, requested REAL, decided_by TEXT, decided REAL, reason TEXT);
CREATE TABLE IF NOT EXISTS finance(id INTEGER PRIMARY KEY, date TEXT NOT NULL, kind TEXT NOT NULL CHECK(kind IN ('receita','despesa','proposta')),
  client_id TEXT, description TEXT NOT NULL, amount_cents INT NOT NULL, status TEXT, created_by TEXT, created REAL);
CREATE TABLE IF NOT EXISTS settings(k TEXT PRIMARY KEY, v TEXT);
CREATE TABLE IF NOT EXISTS chat_threads(id INTEGER PRIMARY KEY, client_id TEXT NOT NULL, title TEXT, created_by TEXT, created REAL, updated REAL);
CREATE TABLE IF NOT EXISTS chat_messages(id INTEGER PRIMARY KEY, thread_id INT NOT NULL, role TEXT NOT NULL, content TEXT NOT NULL, meta TEXT, created REAL);
"""

MIG = [
    "ALTER TABLE jobs ADD COLUMN attempts INTEGER DEFAULT 0",
    "ALTER TABLE jobs ADD COLUMN paused INTEGER DEFAULT 0",
    "ALTER TABLE jobs ADD COLUMN cancelled INTEGER DEFAULT 0",
    "ALTER TABLE jobs ADD COLUMN plan_json TEXT",
    "ALTER TABLE jobs ADD COLUMN chat_id INTEGER",
    "ALTER TABLE jobs ADD COLUMN progress TEXT",
    "ALTER TABLE sessions ADD COLUMN rotated REAL",
    """CREATE TABLE IF NOT EXISTS chat_threads(id INTEGER PRIMARY KEY, client_id TEXT NOT NULL, title TEXT, created_by TEXT, created REAL, updated REAL)""",
    """CREATE TABLE IF NOT EXISTS chat_messages(id INTEGER PRIMARY KEY, thread_id INT NOT NULL, role TEXT NOT NULL, content TEXT NOT NULL, meta TEXT, created REAL)""",
    "ALTER TABLE chat_threads ADD COLUMN pending TEXT",
]

SCRYPT = dict(n=2 ** 14, r=8, p=1, dklen=32)
SESSION_TTL = 12 * 3600
FAIL_WINDOW, FAIL_MAX = 15 * 60, 5
def hash_pw(pw):
    if not pw or len(pw) < 10: raise ValueError("senha precisa de pelo menos 10 caracteres")
    salt = secrets.token_bytes(16); d = hashlib.scrypt(pw.encode(), salt=salt, **SCRYPT)
    return f"scrypt${SCRYPT['n']}${SCRYPT['r']}${SCRYPT['p']}${salt.hex()}${d.hex()}"
def check_pw(pw, stored):
    try:
        _, n, r, p, salt, d = stored.split("$")
        got = hashlib.scrypt((pw or "").encode(), salt=bytes.fromhex(salt), n=int(n), r=int(r), p=int(p), dklen=len(bytes.fromhex(d)))
        return hmac.compare_digest(got.hex(), d)
    except Exception: return False
_DUMMY = None
def th(tok): return hashlib.sha256(tok.encode()).hexdigest()
class Store:
    def __init__(self, path):
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        self.c = sqlite3.connect(path, check_same_thread=False); self.c.row_factory = sqlite3.Row; self.lock = threading.RLock()
        with self.lock:
            self.c.executescript(SCHEMA); self.c.commit()
            for sql in MIG:
                try: self.c.execute(sql); self.c.commit()
                except sqlite3.OperationalError: pass
        try: os.chmod(path, 0o600)
        except OSError: pass
    def q(self, sql, args=(), one=False):
        with self.lock:
            cur = self.c.execute(sql, args); rows = [dict(r) for r in cur.fetchall()]; self.c.commit()
            return (rows[0] if rows else None) if one else rows
    def x(self, sql, args=()):
        with self.lock: cur = self.c.execute(sql, args); self.c.commit(); return cur.lastrowid
    # users
    def add_user(self, username, password, role="owner", clients=None):
        if role not in ("owner", "viewer"): raise ValueError("papel inválido")
        return self.x("INSERT INTO users(username,role,pw,clients,created) VALUES(?,?,?,?,?)",
                      (username, role, hash_pw(password), json.dumps(clients) if clients is not None else None, time.time()))
    def user(self, uid): return self.q("SELECT id,username,role,clients FROM users WHERE id=?", (uid,), one=True)
    def users(self): return self.q("SELECT id,username,role,clients,created FROM users")
    # login with brute-force limit (per IP and per username)
    def recent_fails(self, ip, username):
        t = time.time() - FAIL_WINDOW
        a = self.q("SELECT COUNT(*) n FROM login_fail WHERE ip=? AND ts>?", (ip, t), one=True)["n"]
        b = self.q("SELECT COUNT(*) n FROM login_fail WHERE username=? AND ts>?", (username, t), one=True)["n"]
        return max(a, b)
    def login(self, username, password, ip):
        """Returns (status, session_token|None, csrf|None). status: ok | bad | locked."""
        global _DUMMY
        if self.recent_fails(ip, username) >= FAIL_MAX: return "locked", None, None
        u = self.q("SELECT * FROM users WHERE username=?", (username,), one=True)
        if _DUMMY is None: _DUMMY = hash_pw("x" * 16)
        ok = check_pw(password, u["pw"] if u else _DUMMY) and u is not None  # constant-ish time even for unknown users
        if not ok:
            self.x("INSERT INTO login_fail(ip,username,ts) VALUES(?,?,?)", (ip, username, time.time())); return "bad", None, None
        self.x("DELETE FROM login_fail WHERE username=?", (username,))
        tok, csrf = secrets.token_urlsafe(32), secrets.token_urlsafe(24)
        self.x("INSERT INTO sessions(th,user_id,csrf,expires,ip) VALUES(?,?,?,?,?)", (th(tok), u["id"], csrf, time.time() + SESSION_TTL, ip))
        return "ok", tok, csrf
    def session(self, tok):
        if not tok: return None
        s = self.q("SELECT * FROM sessions WHERE th=?", (th(tok),), one=True)
        if not s or s["expires"] < time.time(): return None
        u = self.user(s["user_id"]); u["csrf"] = s["csrf"]; u["clients"] = json.loads(u["clients"]) if u["clients"] else None; return u
    def logout(self, tok): self.x("DELETE FROM sessions WHERE th=?", (th(tok or ""),))
    def rotate_session(self, tok, ip):
        """Invalida a sessão atual e emite outra (rotação após login/atividade sensível)."""
        s = self.session(tok)
        if not s: return None, None
        self.logout(tok)
        ntok, csrf = secrets.token_urlsafe(32), secrets.token_urlsafe(24)
        self.x("INSERT INTO sessions(th,user_id,csrf,expires,ip) VALUES(?,?,?,?,?)", (th(ntok), s["id"], csrf, time.time() + SESSION_TTL, ip))
        return ntok, csrf
    # settings
    def get(self, k, default=None):
        r = self.q("SELECT v FROM settings WHERE k=?", (k,), one=True); return json.loads(r["v"]) if r else default
    def set(self, k, v): self.x("INSERT OR REPLACE INTO settings(k,v) VALUES(?,?)", (k, json.dumps(v)))
