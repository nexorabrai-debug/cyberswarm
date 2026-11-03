"""Fila assíncrona do Control. Reaproveita HackerAI + validação externa.
Modos: threads embutidas (padrão) OU daemon externo (`cyberswarm worker`) quando autostart=False / --no-workers.
Checkpoint: jobs 'executando' voltam a 'na_fila' na retomada (attempts++). Dedupe, pause, cancel, limites."""
import datetime, json, os, queue, re, secrets, socket, threading, time, traceback
from urllib.parse import urlparse
from ..scope import client_scope, is_lab, OutOfScope
from ..hacker.planner import plan as make_plan
from ..v2.deterministic import DeterministicGate, is_complex, plan_hash
LAB = "_lab"
SAFE_ID = re.compile(r"^[a-z0-9][a-z0-9-]{1,40}$")
MAX_ATTEMPTS = int(os.environ.get("CYBERSWARM_JOB_ATTEMPTS", "3"))
MAX_CONCURRENT = int(os.environ.get("CYBERSWARM_MAX_CONCURRENT", "2"))
def job_dir(data, cid, jid):
    if cid != LAB and not SAFE_ID.match(cid): raise ValueError("id de cliente inválido")
    return os.path.join(data, "clients", cid, "jobs", str(int(jid)))
def client_record(row):
    return {"id": row["id"], "name": row["name"], "authorization_ref": row["authorization_ref"], "authorized_by": row["authorized_by"],
            "contact": row.get("contact"), "valid_from": row["valid_from"], "valid_until": row["valid_until"],
            "scope": {"hosts": json.loads(row["hosts"]), "paths": json.loads(row["paths"])}}
def _free():
    s = socket.socket(); s.bind(("127.0.0.1", 0)); p = s.getsockname()[1]; s.close(); return p
class Worker:
    def __init__(self, store, data, audit, workers=2, autostart=True):
        self.store, self.data, self.audit = store, data, audit
        self.q = queue.Queue(); self.threads = []; self._lab = None; self.lab_lock = threading.Lock()
        self._active = 0; self._active_lock = threading.Lock(); self.autostart = autostart
        # retomada: jobs interrompidos voltam à fila (até MAX_ATTEMPTS)
        for j in store.q("SELECT id, attempts FROM jobs WHERE status='executando'"):
            att = (j["attempts"] or 0) + 1
            if att >= MAX_ATTEMPTS:
                store.x("UPDATE jobs SET status='erro', error=?, finished=?, attempts=? WHERE id=?",
                        ("interrompida demais vezes", time.time(), att, j["id"]))
                audit.log("job_interrupted_final", job=j["id"], attempts=att)
            else:
                store.x("UPDATE jobs SET status='na_fila', attempts=?, error=? WHERE id=?",
                        (att, f"retomada após interrupção (tentativa {att})", j["id"]))
                audit.log("job_resumed", job=j["id"], attempts=att)
        if autostart:
            for _ in range(workers):
                t = threading.Thread(target=self._loop, daemon=True); t.start(); self.threads.append(t)
            for j in store.q("SELECT id FROM jobs WHERE status='na_fila' AND COALESCE(paused,0)=0 AND COALESCE(cancelled,0)=0 ORDER BY id"):
                self.q.put(j["id"])
    def create(self, user, kind, client_id, goal=None, target=None, lab=None, plan=None, chat_id=None):
        s = self.store
        if kind not in ("hacker", "extval"): raise ValueError("tipo de tarefa inválido")
        if client_id == LAB:
            if kind == "hacker": targets = {"lab": True}
            else:
                from ..extval.labs import LABS
                if lab not in LABS or LABS[lab]["kind"] == "skip": raise ValueError("laboratório não registrado/executável")
                targets = {"lab": lab}
        else:
            if kind != "hacker": raise ValueError("validação externa é só para laboratórios")
            row = s.q("SELECT * FROM clients WHERE id=?", (client_id,), one=True)
            if not row: raise OutOfScope("cliente não cadastrado")
            sc = client_scope({client_id: client_record(row)}, client_id)
            if not target or urlparse(target).scheme not in ("http", "https"): raise ValueError("alvo precisa ser URL http(s)")
            sc.check(target); targets = {"url": target}
        goal = (goal or "auditoria defensiva web").strip()[:500]
        # dedupe: mesma missão ainda na fila / executando / aguardando
        dup = s.q("SELECT id FROM jobs WHERE client_id=? AND kind=? AND goal=? AND targets=? AND status IN ('na_fila','executando','aguardando_aprovacao','criada') LIMIT 1",
                  (client_id, kind, goal, json.dumps(targets)), one=True)
        if dup: self.audit.log("job_deduped", job=dup["id"], by=user["username"]); return dup["id"]
        # modo determinístico: operações complexas precisam de plano pré-aprovado
        P = plan
        if kind == "hacker" and client_id != LAB:
            P = P or make_plan(goal, targets, lab=False)
            if s.get("deterministic", False) and is_complex(P["tasks"]):
                gate = DeterministicGate(os.path.join(self.data, "preapproved_plans.json"), self.audit)
                ok, why, _ = gate.check(P["tasks"], client_id)
                if not ok: raise ValueError(f"modo determinístico: {why}")
        elif kind == "hacker" and client_id == LAB and plan is None:
            P = None  # o engine planeja com alvos reais do lab
        jid = s.x("INSERT INTO jobs(client_id,kind,goal,targets,status,created_by,created,plan_json,chat_id,attempts) VALUES(?,?,?,?,?,?,?,?,?,0)",
                  (client_id, kind, goal, json.dumps(targets), "criada", user["username"], time.time(),
                   json.dumps({k: P[k] for k in ("modules", "skipped", "goal") if P}, ensure_ascii=False) if P else None, chat_id))
        os.makedirs(job_dir(self.data, client_id, jid), exist_ok=True)
        self.audit.log("job_created", job=jid, client=client_id, kind=kind, by=user["username"], target=target or lab or "lab-interno")
        pend = []
        if client_id != LAB:
            P = P or make_plan(goal, targets, lab=False)
            for t in P["tasks"]:
                if t["kind"] == "scan" and t["active"] and not is_lab(t["target"]):
                    aid = s.x("INSERT INTO approvals(job_id,op,target,client_id,detail,requested_by,requested) VALUES(?,?,?,?,?,?,?)",
                              (jid, "active_client_test", t["target"], client_id, f"módulo {t['module']} ({t['agent']}) faz teste ativo", user["username"], time.time()))
                    pend.append(aid); self.audit.log("approval_requested", approval=aid, job=jid, operation="active_client_test", target=t["target"], client=client_id)
        if pend: s.x("UPDATE jobs SET status='aguardando_aprovacao' WHERE id=?", (jid,))
        else: self.enqueue(jid)
        return jid
    def enqueue(self, jid):
        self.store.x("UPDATE jobs SET status='na_fila', paused=0 WHERE id=? AND COALESCE(cancelled,0)=0", (jid,))
        if self.autostart: self.q.put(jid)
    def pause(self, user, jid):
        j = self.store.q("SELECT * FROM jobs WHERE id=?", (jid,), one=True)
        if not j: raise KeyError("tarefa inexistente")
        if j["status"] not in ("na_fila", "executando", "aguardando_aprovacao"): raise ValueError("não pausável neste estado")
        self.store.x("UPDATE jobs SET paused=1, status='pausada' WHERE id=?", (jid,))
        self.audit.log("job_paused", job=jid, by=user["username"]); return "pausada"
    def cancel(self, user, jid):
        j = self.store.q("SELECT * FROM jobs WHERE id=?", (jid,), one=True)
        if not j: raise KeyError("tarefa inexistente")
        if j["status"] in ("concluida", "erro", "cancelada"): raise ValueError("já finalizada")
        self.store.x("UPDATE jobs SET cancelled=1, status='cancelada', finished=? WHERE id=?", (time.time(), jid))
        self.audit.log("job_cancelled", job=jid, by=user["username"]); return "cancelada"
    def resume_paused(self, user, jid):
        j = self.store.q("SELECT * FROM jobs WHERE id=?", (jid,), one=True)
        if not j or j["status"] != "pausada": raise ValueError("não está pausada")
        self.store.x("UPDATE jobs SET paused=0 WHERE id=?", (jid,)); self.enqueue(jid)
        self.audit.log("job_unpaused", job=jid, by=user["username"]); return "na_fila"
    def decide(self, user, aid, approve, reason):
        s = self.store; a = s.q("SELECT * FROM approvals WHERE id=?", (aid,), one=True)
        if not a: raise KeyError("aprovação inexistente")
        if a["status"] != "pendente": raise ValueError("aprovação já decidida")
        if not (reason or "").strip(): raise ValueError("justificativa obrigatória")
        st = "aprovada" if approve else "negada"
        s.x("UPDATE approvals SET status=?,decided_by=?,decided=?,reason=? WHERE id=?", (st, user["username"], time.time(), reason.strip()[:500], aid))
        self.audit.log("approval_" + ("granted" if approve else "denied"), approval=aid, job=a["job_id"], operation=a["op"], target=a["target"], client=a["client_id"], by=user["username"], reason=reason.strip()[:200])
        left = s.q("SELECT COUNT(*) n FROM approvals WHERE job_id=? AND status='pendente'", (a["job_id"],), one=True)["n"]
        if left == 0:
            ok = s.q("SELECT * FROM approvals WHERE job_id=? AND status='aprovada'", (a["job_id"],))
            if ok:
                tok = secrets.token_urlsafe(24); d = job_dir(self.data, a["client_id"], a["job_id"])
                recs = [{"token": tok, "op": x["op"], "target": x["target"], "client_id": x["client_id"], "approved_by": x["decided_by"],
                         "expires": datetime.date.today().isoformat()} for x in ok]
                p = os.path.join(d, "approvals.json"); json.dump({"approvals": recs}, open(p, "w"), indent=1); os.chmod(p, 0o600)
                s.x("UPDATE jobs SET approval_token=? WHERE id=?", (tok, a["job_id"]))
            self.enqueue(a["job_id"])
        return st
    def lab_targets(self):
        with self.lab_lock:
            if not self._lab:
                from ..lab import start, start_https
                from ..hacker.engine import lab_targets
                hp, sp = _free(), _free(); self._lab = (start(hp), start_https(sp), lab_targets(f"http://127.0.0.1:{hp}", f"https://127.0.0.1:{sp}"))
            return self._lab[2]
    def claim_next(self):
        """Usado pelo daemon externo: pega o próximo job na_fila atomicamente."""
        with self._active_lock:
            if self._active >= MAX_CONCURRENT: return None
        rows = self.store.q("SELECT id FROM jobs WHERE status='na_fila' AND COALESCE(paused,0)=0 AND COALESCE(cancelled,0)=0 ORDER BY id LIMIT 1")
        if not rows: return None
        jid = rows[0]["id"]
        # claim otimista
        self.store.x("UPDATE jobs SET status='executando', started=COALESCE(started,?), attempts=COALESCE(attempts,0)+1 WHERE id=? AND status='na_fila'",
                     (time.time(), jid))
        j = self.store.q("SELECT * FROM jobs WHERE id=?", (jid,), one=True)
        if not j or j["status"] != "executando": return None
        return jid
    def _loop(self):
        while True:
            jid = self.q.get()
            try:
                with self._active_lock:
                    while self._active >= MAX_CONCURRENT: time.sleep(0.2)
                    self._active += 1
                try: self.run_job(jid)
                finally:
                    with self._active_lock: self._active -= 1
            finally: self.q.task_done()
    def run_job(self, jid):
        s = self.store; j = s.q("SELECT * FROM jobs WHERE id=?", (jid,), one=True)
        if not j: return
        if j.get("cancelled"): s.x("UPDATE jobs SET status='cancelada', finished=? WHERE id=?", (time.time(), jid)); return
        if j.get("paused") and j["status"] == "pausada": return
        if j["status"] == "na_fila":
            s.x("UPDATE jobs SET status='executando', started=?, attempts=COALESCE(attempts,0)+1 WHERE id=?", (time.time(), jid))
        elif j["status"] != "executando": return
        self.audit.log("job_start", job=jid, attempts=j.get("attempts") or 0)
        out = job_dir(self.data, j["client_id"], jid); tg = json.loads(j["targets"]); os.makedirs(out, exist_ok=True)
        # marca progresso
        def prog(msg): s.x("UPDATE jobs SET progress=? WHERE id=?", (msg[:500], jid))
        try:
            if j.get("cancelled"): raise RuntimeError("cancelada")
            if j["kind"] == "extval":
                from ..extval.runner import run_lab
                prog("validação externa…")
                res, _ = run_lab(tg["lab"], out, mode="1.1", use_nuclei=False, use_mobsf=False)
                summ = {k: v for k, v in res.items() if k != "achados"}
                if res.get("erro"): raise RuntimeError(res["erro"])
            else:
                from ..hacker.engine import HackerAI
                prog("Hacker AI planejando…")
                if j["client_id"] == LAB:
                    targets, scope, meta, cid = self.lab_targets(), None, None, None
                else:
                    row = s.q("SELECT * FROM clients WHERE id=?", (j["client_id"],), one=True); rec = client_record(row)
                    json.dump({"clients": [rec]}, open(os.path.join(out, "clients.json"), "w"), indent=1, ensure_ascii=False)
                    scope = client_scope({rec["id"]: rec}, rec["id"]); targets, cid = tg, rec["id"]
                    meta = {"client_name": rec["name"], "authorization_ref": rec["authorization_ref"]}
                # fila v2 por missão (checkpoint por tarefa de varredura)
                qpath = os.path.join(out, "v2queue.db")
                h = HackerAI(out, approvals_path=os.path.join(out, "approvals.json"))
                prog("executando módulos…")
                r = h.run(j["goal"], targets, scope=scope, client=cid, token=j["approval_token"], meta=meta,
                          persist_queue=qpath)
                summ = {k: r[k] for k in ("hacker_run", "core_run", "goal", "modules", "skipped", "denied", "findings", "confirmed", "elapsed_s", "metrics", "new", "recurring", "tools") if k in r}
                if r.get("plan"): s.x("UPDATE jobs SET plan_json=? WHERE id=?", (json.dumps({"modules": r["plan"]["modules"], "skipped": r["plan"]["skipped"], "goal": r["plan"]["goal"]}, ensure_ascii=False), jid))
            if s.q("SELECT cancelled FROM jobs WHERE id=?", (jid,), one=True).get("cancelled"):
                s.x("UPDATE jobs SET status='cancelada', finished=? WHERE id=?", (time.time(), jid)); return
            s.x("UPDATE jobs SET status='concluida', finished=?, summary=?, progress=? WHERE id=?",
                (time.time(), json.dumps(summ, default=str, ensure_ascii=False), "concluída", jid))
            self.audit.log("job_done", job=jid)
        except Exception as e:
            s.x("UPDATE jobs SET status='erro', finished=?, error=?, progress=? WHERE id=?", (time.time(), repr(e)[:500], "erro", jid))
            self.audit.log("job_error", job=jid, error=repr(e)[:200]); traceback.print_exc()
