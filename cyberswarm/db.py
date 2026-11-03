import json, sqlite3, time
SCHEMA = """
CREATE TABLE IF NOT EXISTS runs(id INTEGER PRIMARY KEY, started REAL, finished REAL, target TEXT, client TEXT, status TEXT);
CREATE TABLE IF NOT EXISTS tasks(id INTEGER PRIMARY KEY, run_id INT, agent TEXT, target TEXT, status TEXT, error TEXT, created REAL, finished REAL);
CREATE TABLE IF NOT EXISTS findings(id INTEGER PRIMARY KEY, run_id INT, fingerprint TEXT, agent TEXT, check_id TEXT, title TEXT, severity TEXT,
  status TEXT, target TEXT, evidence TEXT, impact TEXT, recommendation TEXT, repro TEXT, proof TEXT, refs TEXT);
CREATE INDEX IF NOT EXISTS fp ON findings(run_id, fingerprint);
"""
class DB:
    def __init__(self, path=":memory:"):
        self.c = sqlite3.connect(path); self.c.row_factory = sqlite3.Row
        cols = [r[1] for r in self.c.execute("PRAGMA table_info(findings)")]
        if cols and "fingerprint" not in cols:  # migrate v0.1/v0.2 db
            self.c.execute("ALTER TABLE findings RENAME TO findings_legacy"); self.c.execute("DROP INDEX IF EXISTS fp")
        rcols = [r[1] for r in self.c.execute("PRAGMA table_info(runs)")]
        if rcols and "client" not in rcols: self.c.execute("ALTER TABLE runs ADD COLUMN client TEXT")
        self.c.executescript(SCHEMA)
    def new_run(self, target, client=None):
        cur = self.c.execute("INSERT INTO runs(started,target,client,status) VALUES(?,?,?,?)", (time.time(), target, client, "running")); self.c.commit(); return cur.lastrowid
    def finish_run(self, rid, status="done"):
        self.c.execute("UPDATE runs SET finished=?,status=? WHERE id=?", (time.time(), status, rid)); self.c.commit()
    def run(self, rid): r = self.c.execute("SELECT * FROM runs WHERE id=?", (rid,)).fetchone(); return dict(r) if r else None
    def add_task(self, rid, agent, target):
        cur = self.c.execute("INSERT INTO tasks(run_id,agent,target,status,created) VALUES(?,?,?,?,?)", (rid, agent, target, "queued", time.time())); self.c.commit(); return cur.lastrowid
    def update_task(self, tid, status, error=None):
        self.c.execute("UPDATE tasks SET status=?,error=?,finished=? WHERE id=?", (status, error, time.time(), tid)); self.c.commit()
    def add_finding(self, rid, f):
        self.c.execute("INSERT INTO findings(run_id,fingerprint,agent,check_id,title,severity,status,target,evidence,impact,recommendation,repro,proof,refs) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (rid, f["fingerprint"], f["agent"], f["check_id"], f["title"], f["severity"], f["status"], f["target"], f["evidence"], f["impact"],
             f["recommendation"], f["repro"], json.dumps(f["proof"], ensure_ascii=False), json.dumps(f["refs"]))); self.c.commit()
    def findings(self, rid):
        out = []
        for r in self.c.execute("SELECT * FROM findings WHERE run_id=?", (rid,)):
            d = dict(r); d["proof"] = json.loads(d["proof"] or "{}"); d["refs"] = json.loads(d["refs"] or "[]"); out.append(d)
        return out
    def tasks(self, rid): return [dict(r) for r in self.c.execute("SELECT * FROM tasks WHERE run_id=?", (rid,))]
