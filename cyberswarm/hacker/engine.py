"""Hacker AI 1.0 engine: plan -> approval gate -> tool selection -> parallel execution (core Orchestrator, per DAG level)
-> hypothesis-driven lab PoC -> validation -> independent verification -> threat intel / vuln research -> operational
memory -> metrics vs ground truth -> reports (core report system). All agents talk through the Bus (docs/INTERFACES.md)."""
import asyncio, json, os, time
from ..audit import Audit
from ..db import DB
from ..log import get_logger
from ..net import Net
from ..orchestrator import Ctx, Orchestrator
from ..registry import load_all
from ..report import write_reports
from urllib.parse import urlparse
from ..scope import LABDATA, LAB_HOSTS, Scope, is_lab
from ..agents.validation import validate
from ..agents.network import DATASTORE
from .approvals import ApprovalGate
from .bus import Bus
from .memory import Memory
from .planner import plan as make_plan
from .selector import select
from .intel import threat_intel, vuln_research
from .verify import verify_all, reevaluate_hypotheses
from .metrics import load_gt, evaluate
TRIGGERS = {"web.exposed.env", "web.exposed.git", "web.cors.reflect_creds"}
def lab_targets(http_url, https_url):
    p = lambda *a: os.path.join(LABDATA, *a)
    return {"url": http_url, "https": https_url, "spec": p("openapi.json"), "iac": p("terraform"), "manifest": p("android"),
            "plist": p("ios"), "code": p("src"), "ai": p("ai"), "tcp": "tcp://127.0.0.1"}
class HackerAI:
    def __init__(self, out, approvals_path=None, rate=20.0, timeout=5.0, max_requests=1000, workers=6, retries=1, task_timeout=180):
        os.makedirs(out, exist_ok=True); self.out = out
        self.audit = Audit(os.path.join(out, "audit.log")); self.memory = Memory(os.path.join(out, "hacker_memory.db"))
        self.gate = ApprovalGate(approvals_path or os.path.join(os.getcwd(), "approvals.json"), self.audit)
        self.rate, self.timeout, self.max_requests, self.workers, self.retries, self.task_timeout = rate, timeout, max_requests, workers, retries, task_timeout
        self.log = get_logger("hacker")
    def _ctx(self, scope, options):
        return Ctx(scope, self.log, Net(scope, self.audit, rate_per_sec=self.rate, timeout=self.timeout, max_requests=self.max_requests), self.audit, options)
    def run(self, goal, targets, scope=None, client=None, token=None, ports=None, pdf=True, meta=None, force_tools=None, persist_queue=None, should_stop=None):
        t0 = time.monotonic(); scope = scope or Scope.lab(); lab = scope.client is None and all(urlparse(v).hostname in LAB_HOSTS for v in targets.values() if v and "://" in v)
        hrun = self.memory.start_run(goal if isinstance(goal, str) else json.dumps(goal)); bus = Bus(hrun, self.memory)
        P = make_plan(goal, targets, lab=lab); bus.publish("plan", "planner", {"modules": P["modules"], "tasks": len(P["tasks"]), "skipped": P["skipped"], "levels": P["levels"]})
        self.audit.log("hacker_plan", run=hrun, modules=P["modules"], tasks=len(P["tasks"]), lab=lab)
        # approval gate: active tests outside the lab
        denied = []
        for t in P["tasks"]:
            if t["kind"] != "scan" or not t["active"] or is_lab(t["target"]): continue
            try: scope.check(t["target"]); op = "active_client_test"
            except Exception: op = "out_of_scope"
            ok = self.gate.check(op, t["target"], token, client)
            bus.publish("approval", "gate", {"task": t["id"], "op": op, "target": t["target"], "granted": ok})
            if not ok: denied.append(t["id"])
        P["tasks"] = [t for t in P["tasks"] if t["id"] not in denied]; P["denied"] = denied
        # tool selection
        ttype = {"codesec": "code", "network": "tcp"}; tools = {}
        for t in P["tasks"]:
            if t["kind"] == "scan" and t["agent"] not in tools:
                s = select(t["module"], ttype.get(t["module"], ""), self.memory); tools[t["agent"]] = s["tool"]
                bus.publish("tool_selection", "selector", s)
        tools.update(force_tools or {})
        options = {"tools": tools, "api_base": targets.get("url"), "ports": ports or sorted({*DATASTORE, *self._lab_ports(targets)})}
        core = DB(os.path.join(self.out, "cyberswarm.db")); ctx = self._ctx(scope, options)
        perf = []
        def on_task(name, target, status, n, secs, attempts):
            tool = tools.get(name, "builtin"); used = ctx.options.get("tool_used", {}).get(name, tool)
            self.memory.record_tool(used, name, status in ("done", "partial"), secs); perf.append({"agent": name, "tool": used, "status": status, "findings": n, "secs": round(secs, 2), "attempts": attempts})
            bus.publish("task_result", name, {"target": target, "status": status, "findings": n, "secs": round(secs, 3), "attempts": attempts, "tool": used})
        orch = Orchestrator(ctx, core, workers=self.workers, task_timeout=self.task_timeout, retries=self.retries, on_task=on_task)
        rid = core.new_run(f"hacker:{P['goal'][:60]}", client); raw = []; byid = {t["id"]: t for t in P["tasks"]}
        # Monta jobs por nível (exploitlab condicional)
        if persist_queue:
            from ..v2.queue import PersistentQueue, run_job
            from ..v2.cache import ResultCache
            pq = PersistentQueue(persist_queue); cache = ResultCache(persist_queue + ".cache")
            if pq.recovered: self.audit.log("v2_resume", run=hrun, recovered=pq.recovered)
        for li, level in enumerate(P["levels"]):
            if should_stop and (why := should_stop()):
                from ..v2.queue import Stopped
                raise Stopped(why)
            jobs = []
            for tid in level:
                t = byid.get(tid)
                if not t or t["kind"] != "scan": continue
                if t["module"] == "exploitlab":
                    hits = sorted({f["check_id"] for f in raw if f["check_id"] in TRIGGERS})
                    hid = self.memory.add_hypothesis(hrun, "poc:" + t["target"], "exposição observada pelo módulo web é reproduzível (PoC de laboratório)", "aberta", ",".join(hits))
                    t["hypothesis"] = hid
                    if not hits: self.memory.update_hypothesis(hid, "descartada", "nenhum gatilho web"); continue
                bus.publish("task", "planner", {"task": tid, "agent": t["agent"], "target": t["target"]}, recipient=t["agent"]); jobs.append((t["agent"], t["target"]))
            if not jobs: continue
            if persist_queue:
                job_id = f"L{li}-" + ",".join(sorted(a for a, _ in jobs))  # estável entre retomadas
                pq.add(job_id, jobs)
                run_job(pq, job_id, ctx, cache=cache, task_timeout=self.task_timeout, retries=self.retries, on_task=on_task, core_db=core, run_id=rid, should_stop=should_stop)
                raw += pq.findings(job_id)
            else:
                raw += asyncio.run(orch.run(jobs, "hacker", client, rid=rid, finalize=False))[1]
        findings = validate(raw)
        for f in findings: bus.publish("finding", f["agent"], {"fingerprint": f["fingerprint"], "check_id": f["check_id"], "status": f["status"], "severity": f["severity"]})
        for t in P["tasks"]:
            if t.get("hypothesis"):
                poc = [f for f in findings if f["agent"] == "exploitlab"]
                h = [x for x in self.memory.hypotheses(hrun) if x["id"] == t["hypothesis"]][0]
                if h["status"] == "aberta": self.memory.update_hypothesis(t["hypothesis"], "confirmada" if poc else "refutada", f"{len(poc)} PoC reproduzidas")
        vsum = verify_all(findings, load_all(), lambda: self._ctx(scope, dict(options)), tools, bus, self.memory, hrun)
        changes = reevaluate_hypotheses(findings, self.memory, hrun, bus, {t['agent'] for t in P['tasks'] if t['kind'] == 'scan'})
        n_ti = threat_intel(findings); chains = vuln_research(findings)
        for f in findings:
            f["refs"] = sorted(set(f["refs"]) | {a.split()[0] for a in f["intel"]["attack"]})
            f["memory"] = self.memory.record_finding(hrun, f); core.add_finding(rid, f)
        core.finish_run(rid)
        metrics = None
        if lab:
            hp, sp = self._port(targets.get("url") or ":0"), self._port(targets.get("https") or ":0")
            subst = {"http": hp, "https": sp, "tcp_http": f"tcp://127.0.0.1:{hp}", "tcp_https": f"tcp://127.0.0.1:{sp}"}
            metrics = evaluate(findings, load_gt(subst=subst), {t["agent"] for t in P["tasks"] if t["kind"] == "scan"})
            for agent, m in metrics["per_module"].items():
                self.memory.record_quality(ctx.options.get("tool_used", {}).get(agent, tools.get(agent, "builtin")), agent, m["tp"], m["fp"])
            bus.publish("metric", "evaluator", {k: metrics[k] for k in ("tp", "fp", "fn", "precision", "recall", "f1")})
        elapsed = round(time.monotonic() - t0, 2)
        summary = {"hacker_run": hrun, "core_run": rid, "goal": P["goal"], "modules": P["modules"], "skipped": P["skipped"], "denied": denied,
                   "tools": tools, "tool_used": ctx.options.get("tool_used", {}), "perf": perf, "verification": vsum, "hypotheses": self.memory.hypotheses(hrun),
                   "hypothesis_changes": changes, "threat_intel_enriched": n_ti, "chains": chains, "metrics": metrics, "elapsed_s": elapsed,
                   "messages": len(bus.log), "new": sum(f["memory"] == "novo" for f in findings), "recurring": sum(f["memory"] == "recorrente" for f in findings),
                   "findings": len(findings), "confirmed": sum(f["status"] == "confirmado" for f in findings)}
        self.memory.finish_run(hrun, rid, {"metrics": metrics, "elapsed_s": elapsed, "findings": len(findings)})
        meta = meta or {"client_name": "Laboratório CyberSwarm (Hacker AI 1.0)", "authorization_ref": "LAB (127.0.0.1, ambiente próprio)"}
        r = write_reports(core, rid, self.out, meta, pdf=pdf, extra=self._extra(P, summary, findings))
        json.dump({**summary, "plan": P, "research": {f["fingerprint"]: f["research"] for f in findings}, "bus": bus.log}, open(os.path.join(self.out, f"hacker-{hrun}.json"), "w"), indent=1, ensure_ascii=False, default=str)
        self.audit.log("hacker_done", run=hrun, core_run=rid, findings=len(findings), elapsed=elapsed)
        summary["reports"] = r; summary["plan"] = P; summary["findings_list"] = findings
        return summary
    @staticmethod
    def _port(u): return u.rstrip('/').rsplit(':', 1)[-1]
    @staticmethod
    def _lab_ports(targets):
        out = set()
        for k in ("url", "https"):
            v = targets.get(k)
            if v and v.rsplit(":", 1)[-1].strip("/").isdigit(): out.add(int(v.rsplit(":", 1)[-1].strip("/")))
        return out
    def _extra(self, P, s, findings):
        lv = [f"Nível {i}: " + ", ".join(f"{t} ({next((x['module'] for x in P['tasks'] if x['id']==t), '-')})" for t in l) for i, l in enumerate(P["levels"])]
        m = s["metrics"]; v = s["verification"]
        sec = [("Hacker AI 1.0 - objetivo e plano", [f"Objetivo: {P['goal']}", f"Módulos: {', '.join(P['modules'])}"] + lv +
                [f"Ignorado: {a} ({b})" for a, b in P["skipped"]] + [f"Negado pelo portão de aprovação: {d}" for d in s["denied"]]),
               ("Ferramentas selecionadas", [f"{a}: {t} (usada: {s['tool_used'].get(a, t)})" for a, t in s["tools"].items()] +
                [f"{p['agent']} {p['status']} {p['findings']} achados em {p['secs']}s, tentativas {p['attempts']}" for p in s["perf"]]),
               ("Verificação independente", [f"Confirmados re-verificados: {v['checked']}; reproduzidos: {v['reproduced']}; rebaixados: {v['downgraded']}; corroborados por outra ferramenta: {v['corroborated']}",
                                             "Verificadores: " + ", ".join(f"{a}={t}" for a, t in v["tools"].items())] + [f"Erro: {e}" for e in v["errors"]]),
               ("Hipóteses", [f"#{h['id']} [{h['status']}] {h['statement']}" for h in s["hypotheses"]] or ["nenhuma"]),
               ("Cadeias de ataque correlacionadas (pesquisa de vulnerabilidades)", [f"{c['name']}: {c['narrative']} Evidência: {', '.join(c['evidence'])}" for c in s["chains"]] or ["nenhuma"]),
               ("Memória operacional", [f"Achados novos: {s['new']}; recorrentes: {s['recurring']} (histórico em hacker_memory.db; não é treinamento de modelo)"])]
        if m: sec.append(("Desempenho vs. gabarito do laboratório", [f"Precisão {m['precision']} | Revocação {m['recall']} | F1 {m['f1']} (VP {m['tp']}, FP {m['fp']}, FN {m['fn']})"] +
                          [f"{a}: VP {x['tp']} FP {x['fp']} FN {x['fn']}" for a, x in m["per_module"].items()] +
                          [f"Falso negativo: {a} {b}" for a, b in m["false_negatives"]] + [f"Falso positivo: {a} {b}" for a, b in m["false_positives"]]))
        return sec
