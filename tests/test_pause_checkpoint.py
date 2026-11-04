"""Pausa/cancelamento de tarefa EM EXECUÇÃO respeitam o checkpoint; retomada continua do checkpoint."""
import sqlite3, glob
from cyberswarm.control.store import Store
from cyberswarm.control.worker import Worker
from cyberswarm.audit import Audit
import cyberswarm.v2.queue as Q
U = {"username": "dono", "role": "owner", "clients": None}
def _w(tmp_path):
    st = Store(str(tmp_path / "control.db")); return st, Worker(st, str(tmp_path), Audit(str(tmp_path / "a.log")), autostart=False)
def _stop_after_first(monkeypatch, st, jid, col):
    orig = Q.PersistentQueue.checkpoint; n = {"c": 0}
    def cp(self, *a, **k):
        orig(self, *a, **k); n["c"] += 1
        if n["c"] == 1:
            st.x(f"UPDATE jobs SET {col}=1" + (", status='pausada'" if col == "paused" else "") + " WHERE id=?", (jid,))
    monkeypatch.setattr(Q.PersistentQueue, "checkpoint", cp); return orig
def _qstats(tmp_path):
    db = glob.glob(str(tmp_path / "clients" / "_lab" / "jobs" / "*" / "v2queue.db"))[0]
    return dict(sqlite3.connect(db).execute("SELECT status,COUNT(*) FROM q GROUP BY status").fetchall())
def test_pause_running_then_resume_from_checkpoint(tmp_path, monkeypatch):
    st, w = _w(tmp_path); jid = w.create(U, "hacker", "_lab", "auditar laboratório completo", None, None)
    orig = _stop_after_first(monkeypatch, st, jid, "paused")
    w.run_job(jid)
    j = st.q("SELECT * FROM jobs WHERE id=?", (jid,), one=True)
    assert j["status"] == "pausada" and j["finished"] is None, j
    s1 = _qstats(tmp_path); assert s1.get("done", 0) + s1.get("error", 0) == 1 and s1.get("pending", 0) >= 1, s1
    monkeypatch.setattr(Q.PersistentQueue, "checkpoint", orig)
    assert w.resume_paused(U, jid) == "na_fila"
    claimed = []; oc = Q.PersistentQueue.claim
    def cl(self, job):
        r = oc(self, job); claimed.append(r); return r
    monkeypatch.setattr(Q.PersistentQueue, "claim", cl)
    w.run_job(jid)
    j = st.q("SELECT * FROM jobs WHERE id=?", (jid,), one=True)
    assert j["status"] == "concluida", j
    s2 = _qstats(tmp_path); assert s2.get("pending", 0) == 0 and s2.get("running", 0) == 0
    first_job_tasks = sum(s1.values())
    assert len([c for c in claimed if c]) == sum(s2.values()) - 1, "tarefa já feita não pode rodar de novo"
def test_cancel_running_stops_at_checkpoint(tmp_path, monkeypatch):
    st, w = _w(tmp_path); jid = w.create(U, "hacker", "_lab", "auditar laboratório completo", None, None)
    st.x("UPDATE jobs SET status='na_fila' WHERE id=?", (jid,))
    _stop_after_first(monkeypatch, st, jid, "cancelled")
    w.run_job(jid)
    assert st.q("SELECT status FROM jobs WHERE id=?", (jid,), one=True)["status"] == "cancelada"
    assert _qstats(tmp_path).get("pending", 0) >= 1
def test_pause_at_end_not_overwritten(tmp_path, monkeypatch):
    st, w = _w(tmp_path); jid = w.create(U, "hacker", "_lab", "auditar laboratório web", None, None)
    import cyberswarm.hacker.engine as E; orun = E.HackerAI.run
    def run(self, *a, **k):
        r = orun(self, *a, **k); st.x("UPDATE jobs SET paused=1, status='pausada' WHERE id=?", (jid,)); return r
    monkeypatch.setattr(E.HackerAI, "run", run)
    w.run_job(jid)
    assert st.q("SELECT status FROM jobs WHERE id=?", (jid,), one=True)["status"] == "pausada"
