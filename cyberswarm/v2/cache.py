"""Cache de resultados. Chave = sha256(agente, alvo, versão do núcleo, impressão digital do conteúdo).
- Alvo caminho: impressão = hash de (caminho relativo, tamanho, mtime_ns) de todos os arquivos -> qualquer mudança invalida.
- Alvo URL: só com TTL explícito (padrão 0 = não cacheia), pois o serviço remoto pode mudar sem aviso."""
import hashlib, json, os, sqlite3, time
from .. import __version__ as CORE_VER
def fingerprint(target):
    h = hashlib.sha256()
    if os.path.isfile(target): paths = [target]
    elif os.path.isdir(target): paths = sorted(os.path.join(d, f) for d, _, fs in os.walk(target) for f in fs)
    else: return None
    for p in paths:
        st = os.stat(p); h.update(f"{os.path.relpath(p, target)}|{st.st_size}|{st.st_mtime_ns}\n".encode())
    return h.hexdigest()
class ResultCache:
    def __init__(self, path, url_ttl=0):
        self.c = sqlite3.connect(path, isolation_level=None, check_same_thread=False); self.url_ttl = url_ttl
        self.c.execute("CREATE TABLE IF NOT EXISTS cache(k TEXT PRIMARY KEY, created REAL, findings TEXT)")
        self.hits = self.misses = 0
    def key(self, agent, target):
        is_url = "://" in target
        fp = f"url:{int(time.time() // self.url_ttl)}" if is_url and self.url_ttl else (None if is_url else fingerprint(target))
        return None if fp is None else hashlib.sha256(f"{agent}|{target}|{CORE_VER}|{fp}".encode()).hexdigest()
    def get(self, agent, target):
        k = self.key(agent, target); r = k and self.c.execute("SELECT findings FROM cache WHERE k=?", (k,)).fetchone()
        if r: self.hits += 1; return json.loads(r[0])
        self.misses += 1; return None
    def put(self, agent, target, findings):
        k = self.key(agent, target)
        if k: self.c.execute("INSERT OR REPLACE INTO cache VALUES(?,?,?)", (k, time.time(), json.dumps(findings, default=str)))
