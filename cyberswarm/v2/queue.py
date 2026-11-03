"""Fila persistente (SQLite, WAL) com checkpoint por tarefa e retomada após kill.
- Cada tarefa concluída é gravada atomicamente (status + findings) = checkpoint.
- Ao abrir, tarefas 'running' de um processo morto voltam a 'pending' (attempts preservado; max_attempts evita loop).
- Execução reaproveita o Orchestrator do núcleo (escopo, timeout, retries, PartialResult)."""
import asyncio, json, os, sqlite3, time
from ..orchestrator import Orchestrator
SCHEMA = """CREATE TABLE IF NOT EXISTS q(id INTEGER PRIMARY KEY, job TEXT, agent TEXT, target TEXT, status TEXT DEFAULT 'pending',
 attempts INTEGER DEFAULT 0, pid INTEGER, started REAL, finished REAL, error TEXT, findings TEXT, cached INTEGER DEFAULT 0,
 UNIQUE(job, agent, target));"""
class _TaskDB:
    """Encaminha add/update_task para o DB do núcleo (se fornecido) e guarda o status da tarefa atual."""
    def __init__(self, real=None, rid=None):
        self.real, self.rid, self.status, self.err, self._last = real, rid, None, None, 0
    def new_run(self, *a): return self.rid or 0
    def add_task(self, rid, name, target):
        if self.real: self._last = self.real.add_task(self.rid or rid, name, target); return self._last
        self._last += 1; return self._last
    def update_task(self, tid, st, err=None):
        self.status, self.err = st, err
        if self.real: self.real.update_task(tid, st, err)
class PersistentQueue:
    def __init__(self, path, max_attempts=3):
        self.path, self.max_attempts = path, max_attempts
        self.c = sqlite3.connect(path, isolation_level=None, check_same_thread=False); self.c.execute("PRAGMA journal_mode=WAL")
        self.c.executescript(SCHEMA)
        try: os.chmod(path, 0o600)
        except OSError: pass
        self.recovered = self.c.execute("UPDATE q SET status='pending', pid=NULL WHERE status='running'").rowcount
    def add(self, job, tasks):
        for a, t in tasks: self.c.execute("INSERT OR IGNORE INTO q(job,agent,target) VALUES(?,?,?)", (job, a, t))
    def claim(self, job):
        with self.c:  # BEGIN IMMEDIATE semantics via single connection
            r = self.c.execute("SELECT id,agent,target,attempts FROM q WHERE job=? AND status='pending' ORDER BY id LIMIT 1", (job,)).fetchone()
            if not r: return None
            if r[3] >= self.max_attempts:
                self.c.execute("UPDATE q SET status='error', error='max_attempts' WHERE id=?", (r[0],)); return self.claim(job)
            self.c.execute("UPDATE q SET status='running', attempts=attempts+1, pid=?, started=? WHERE id=?", (os.getpid(), time.time(), r[0]))
            return r[:3]
    def checkpoint(self, tid, status, findings, error=None, cached=False):
        self.c.execute("UPDATE q SET status=?, findings=?, error=?, finished=?, cached=? WHERE id=?",
                       (status, json.dumps(findings, default=str), error, time.time(), int(cached), tid))
    def stats(self, job):
        return dict(self.c.execute("SELECT status, COUNT(*) FROM q WHERE job=? GROUP BY status", (job,)).fetchall())
    def findings(self, job):
        out = []
        for (f,) in self.c.execute("SELECT findings FROM q WHERE job=? AND findings IS NOT NULL ORDER BY id", (job,)): out += json.loads(f)
        return out
def run_job(q, job, ctx, cache=None, task_timeout=120, retries=0, on_task=None, core_db=None, run_id=None):
    """Consome a fila até esvaziar. Pode ser morto a qualquer momento; nova chamada retoma do último checkpoint."""
    while (t := q.claim(job)):
        tid, agent, target = t
        hit = cache.get(agent, target) if cache else None
        if hit is not None:
            q.checkpoint(tid, "done", hit, cached=True); ctx.audit.log("v2_cache_hit", agent=agent, target=target)
            if core_db and run_id:
                xid = core_db.add_task(run_id, agent, target); core_db.update_task(xid, "done")
            if on_task: on_task(agent, target, "done", len(hit), 0.0, 0)
            continue
        db = _TaskDB(core_db, run_id); orch = Orchestrator(ctx, db, workers=1, task_timeout=task_timeout, retries=retries, on_task=on_task)
        _, fs = asyncio.run(orch.run([(agent, target)], label=job, rid=run_id, finalize=False))
        st = db.status or "error"
        q.checkpoint(tid, st, fs, db.err)
        if cache and st == "done": cache.put(agent, target, fs)
    return q.stats(job)
