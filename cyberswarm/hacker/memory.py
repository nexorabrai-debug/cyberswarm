"""Persistent OPERATIONAL memory (SQLite). Stores run history, findings history, tool performance, hypotheses and bus messages.
This is NOT model training: nothing here changes any model weights; it is a database the planner/selector read deterministically.
Memória operacional NÃO é treinamento de modelo: nenhum peso de modelo é alterado."""
import json, sqlite3, time
SCHEMA = """
CREATE TABLE IF NOT EXISTS runs(id INTEGER PRIMARY KEY, goal TEXT, started REAL, finished REAL, core_run INT, metrics TEXT);
CREATE TABLE IF NOT EXISTS findings_history(fingerprint TEXT PRIMARY KEY, check_id TEXT, target TEXT, first_run INT, last_run INT, times_seen INT, last_status TEXT);
CREATE TABLE IF NOT EXISTS tool_perf(tool TEXT, module TEXT, runs INT DEFAULT 0, ok INT DEFAULT 0, fail INT DEFAULT 0, secs REAL DEFAULT 0, tp INT DEFAULT 0, fp INT DEFAULT 0, PRIMARY KEY(tool, module));
CREATE TABLE IF NOT EXISTS hypotheses(id INTEGER PRIMARY KEY, run_id INT, key TEXT, statement TEXT, status TEXT, evidence TEXT, created REAL, updated REAL);
CREATE TABLE IF NOT EXISTS messages(id INTEGER PRIMARY KEY AUTOINCREMENT, run_id INT, msg_id INT, type TEXT, sender TEXT, recipient TEXT, ts REAL, payload TEXT);
"""
class Memory:
    def __init__(self, path=":memory:"):
        self.c = sqlite3.connect(path, check_same_thread=False); self.c.row_factory = sqlite3.Row; self.c.executescript(SCHEMA)
    def start_run(self, goal):
        cur = self.c.execute("INSERT INTO runs(goal,started) VALUES(?,?)", (goal, time.time())); self.c.commit(); return cur.lastrowid
    def finish_run(self, rid, core_run, metrics):
        self.c.execute("UPDATE runs SET finished=?,core_run=?,metrics=? WHERE id=?", (time.time(), core_run, json.dumps(metrics), rid)); self.c.commit()
    def runs(self): return [dict(r) for r in self.c.execute("SELECT * FROM runs ORDER BY id")]
    def record_finding(self, rid, f):
        """Returns 'novo' or 'recorrente'."""
        r = self.c.execute("SELECT times_seen FROM findings_history WHERE fingerprint=?", (f["fingerprint"],)).fetchone()
        if r: self.c.execute("UPDATE findings_history SET last_run=?,times_seen=times_seen+1,last_status=? WHERE fingerprint=?", (rid, f["status"], f["fingerprint"]))
        else: self.c.execute("INSERT INTO findings_history VALUES(?,?,?,?,?,?,?)", (f["fingerprint"], f["check_id"], f["target"], rid, rid, 1, f["status"]))
        self.c.commit(); return "recorrente" if r else "novo"
    def history(self, fp):
        r = self.c.execute("SELECT * FROM findings_history WHERE fingerprint=?", (fp,)).fetchone(); return dict(r) if r else None
    def record_tool(self, tool, module, ok, secs):
        self.c.execute("INSERT OR IGNORE INTO tool_perf(tool,module) VALUES(?,?)", (tool, module))
        self.c.execute("UPDATE tool_perf SET runs=runs+1, ok=ok+?, fail=fail+?, secs=secs+? WHERE tool=? AND module=?", (int(ok), int(not ok), secs, tool, module)); self.c.commit()
    def record_quality(self, tool, module, tp, fp):
        self.c.execute("INSERT OR IGNORE INTO tool_perf(tool,module) VALUES(?,?)", (tool, module))
        self.c.execute("UPDATE tool_perf SET tp=tp+?, fp=fp+? WHERE tool=? AND module=?", (tp, fp, tool, module)); self.c.commit()
    def tool_stats(self, tool, module):
        r = self.c.execute("SELECT * FROM tool_perf WHERE tool=? AND module=?", (tool, module)).fetchone(); return dict(r) if r else None
    def all_tools(self): return [dict(r) for r in self.c.execute("SELECT * FROM tool_perf ORDER BY module, tool")]
    def add_hypothesis(self, rid, key, statement, status="aberta", evidence=""):
        cur = self.c.execute("INSERT INTO hypotheses(run_id,key,statement,status,evidence,created,updated) VALUES(?,?,?,?,?,?,?)", (rid, key, statement, status, evidence, time.time(), time.time()))
        self.c.commit(); return cur.lastrowid
    def update_hypothesis(self, hid, status, evidence):
        self.c.execute("UPDATE hypotheses SET status=?,evidence=?,updated=? WHERE id=?", (status, evidence, time.time(), hid)); self.c.commit()
    def hypotheses(self, rid=None, status=None):
        q, a = "SELECT * FROM hypotheses WHERE 1=1", []
        if rid is not None: q += " AND run_id=?"; a.append(rid)
        if status: q += " AND status=?"; a.append(status)
        return [dict(r) for r in self.c.execute(q + " ORDER BY id", a)]
    def add_message(self, m):
        self.c.execute("INSERT INTO messages(run_id,msg_id,type,sender,recipient,ts,payload) VALUES(?,?,?,?,?,?,?)",
                       (m["run_id"], m["id"], m["type"], m["sender"], m["recipient"], m["ts"], json.dumps(m["payload"], ensure_ascii=False))); self.c.commit()
    def messages(self, rid): return [dict(r) for r in self.c.execute("SELECT * FROM messages WHERE run_id=? ORDER BY id", (rid,))]
