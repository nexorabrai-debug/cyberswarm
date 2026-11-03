"""Scope control: DENY BY DEFAULT.
- Lab (127.0.0.1/localhost + bundled labdata) is always allowed.
- Anything else requires a valid client authorization record (clients.json)."""
import datetime, json, os
from urllib.parse import urlparse
LABDATA = os.path.join(os.path.dirname(os.path.abspath(__file__)), "labdata")
LAB_HOSTS = {"127.0.0.1", "localhost"}
FORBIDDEN_KEYS = {"password", "senha", "token", "secret", "api_key", "apikey", "private_key"}
class OutOfScope(Exception): pass
class Scope:
    def __init__(self, hosts=(), paths=(), client=None):
        self.hosts = {h.lower() for h in hosts} | LAB_HOSTS
        self.paths = [os.path.realpath(p) for p in paths] + [os.path.realpath(LABDATA)]
        self.client = client
    @classmethod
    def lab(cls): return cls()
    def check_url(self, url):
        u = urlparse(url)
        if u.scheme not in ("http", "https", "tcp") or not u.hostname or u.hostname.lower() not in self.hosts:
            raise OutOfScope(f"URL fora do escopo: {url}")
        return True
    def check_path(self, path):
        rp = os.path.realpath(path)
        if not any(rp == p or rp.startswith(p + os.sep) for p in self.paths):
            raise OutOfScope(f"Caminho fora do escopo: {path}")
        return True
    def check(self, target):
        return self.check_url(target) if "://" in target else self.check_path(target)
def is_lab(target):
    try: Scope.lab().check(target); return True
    except OutOfScope: return False
def _walk_keys(o):
    if isinstance(o, dict):
        for k, v in o.items(): yield k; yield from _walk_keys(v)
    elif isinstance(o, list):
        for v in o: yield from _walk_keys(v)
def load_clients(path):
    if not os.path.exists(path): return {}
    with open(path) as f: data = json.load(f)
    bad = [k for k in _walk_keys(data) if k.lower() in FORBIDDEN_KEYS]
    if bad: raise ValueError(f"clients.json não pode guardar credenciais (campos: {bad})")
    return {c["id"]: c for c in data.get("clients", [])}
def client_scope(clients, client_id, today=None):
    today = today or datetime.date.today()
    c = clients.get(client_id)
    if not c: raise OutOfScope(f"Cliente '{client_id}' não cadastrado em clients.json")
    for k in ("authorization_ref", "authorized_by", "valid_from", "valid_until", "scope"):
        if not c.get(k): raise OutOfScope(f"Cliente '{client_id}' sem campo obrigatório: {k}")
    if not (datetime.date.fromisoformat(c["valid_from"]) <= today <= datetime.date.fromisoformat(c["valid_until"])):
        raise OutOfScope(f"Autorização do cliente '{client_id}' fora da validade ({c['valid_from']}..{c['valid_until']})")
    return Scope(c["scope"].get("hosts", []), c["scope"].get("paths", []), client=c)
def resolve_scope(target, clients_path, client_id=None):
    if client_id:
        s = client_scope(load_clients(clients_path), client_id); s.check(target); return s
    if is_lab(target): return Scope.lab()
    raise OutOfScope(f"Alvo fora do laboratório exige --client com autorização registrada: {target}")
