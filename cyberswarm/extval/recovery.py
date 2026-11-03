"""Experimentos REAIS de recuperação (ferramenta morta, timeout, lab fora do ar, estresse). Grava <out>/recovery.json."""
import asyncio, json, os, signal, subprocess, threading, time
from ..scope import Scope
from ..audit import Audit
from ..net import Net
from ..log import get_logger
from ..db import DB
from ..orchestrator import Ctx, Orchestrator
from . import probes, tools_ext  # noqa: F401  (registra agentes)
def _orch(out, opts, jobs, budget=300, **k):
    os.makedirs(out, exist_ok=True); sc = Scope.lab(); au = Audit(os.path.join(out, "audit.log"))
    c = Ctx(sc, get_logger("rec"), Net(sc, au, rate_per_sec=50, max_requests=budget), au, dict(opts)); tasks = []
    o = Orchestrator(c, DB(os.path.join(out, "c.db")), on_task=lambda n, t, s, q, secs, a: tasks.append({"agente": n, "alvo": t, "status": s, "segundos": round(secs, 2)}), **k)
    t0 = time.monotonic(); _, fs = asyncio.run(o.run(jobs)); return {"tarefas": tasks, "achados": len(fs), "segundos": round(time.monotonic() - t0, 2), "stats": c.options.get("tool_stats")}
def killer(after):
    def k():
        time.sleep(after); subprocess.run(["pkill", "-9", "-f", "bin/nuclei -u http://127.0.0.1:5002"])
    threading.Thread(target=k, daemon=True).start()
def main(out):
    R = {}
    R["timeout_nuclei_real"] = _orch(out + "/t1", {"nuclei_timeout": 20}, [("nuclei", "http://127.0.0.1:5002"), ("discovery", "http://127.0.0.1:5002")], task_timeout=120)
    killer(15); R["nuclei_real_morto_SIGKILL_15s"] = _orch(out + "/t2", {}, [("nuclei", "http://127.0.0.1:5002"), ("graphql", "http://127.0.0.1:5013")], task_timeout=300)
    R["lab_fora_do_ar"] = _orch(out + "/t3", {}, [("discovery", "http://127.0.0.1:5999"), ("discovery", "http://127.0.0.1:3000"), ("graphql", "http://127.0.0.1:5013")], retries=1)
    labs = ["http://127.0.0.1:3000", "http://127.0.0.1:5002", "http://127.0.0.1:5013", "http://127.0.0.1:8080/WebGoat"]
    jobs = [(a, u) for u in labs for a in ("web", "discovery", "graphql", "apidata")] * 5
    for key, b in (("estresse_80_tarefas_orcamento_padrao_300", 300), ("estresse_80_tarefas_orcamento_5000", 5000)):
      R[key] = s = _orch(out + "/" + key, {}, jobs, budget=b, workers=16)
      s["por_status"] = {k: sum(t["status"] == k for t in s["tarefas"]) for k in {t["status"] for t in s["tarefas"]}}; s["tarefas"] = len(s["tarefas"])
    json.dump(R, open(os.path.join(out, "recovery.json"), "w"), indent=1, ensure_ascii=False); return R
if __name__ == "__main__":
    import sys; print(json.dumps(main(sys.argv[1]), indent=1, ensure_ascii=False))
