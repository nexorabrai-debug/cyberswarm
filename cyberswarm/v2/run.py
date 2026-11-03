"""python -m cyberswarm.v2.run --db fila.db --job J [--task agente=alvo ...] [--path P] [--cache c.db] [--plugin mod.py]
Enfileira (idempotente) e consome. Se morto, rodar o MESMO comando retoma do último checkpoint."""
import argparse, importlib.util, json, os, sys
from ..audit import Audit
from ..log import get_logger
from ..net import Net
from ..orchestrator import Ctx
from ..scope import Scope
from .queue import PersistentQueue, run_job
from .cache import ResultCache
def main(argv=None):
    ap = argparse.ArgumentParser(); ap.add_argument("--db", required=True); ap.add_argument("--job", required=True)
    ap.add_argument("--task", action="append", default=[]); ap.add_argument("--path", action="append", default=[])
    ap.add_argument("--cache"); ap.add_argument("--plugin"); ap.add_argument("--audit", default=None)
    ap.add_argument("--timeout", type=int, default=120)
    a = ap.parse_args(argv)
    if a.plugin:  # só para testes/extensões locais: registra agentes extras
        s = importlib.util.spec_from_file_location("v2plugin", a.plugin); s.loader.exec_module(importlib.util.module_from_spec(s))
    sc = Scope(paths=a.path); au = Audit(a.audit or os.path.splitext(a.db)[0] + ".audit.log")
    ctx = Ctx(sc, get_logger("v2"), Net(sc, au), au, {})
    q = PersistentQueue(a.db)
    if q.recovered: au.log("v2_resume", job=a.job, recovered=q.recovered)
    q.add(a.job, [tuple(t.split("=", 1)) for t in a.task])
    st = run_job(q, a.job, ctx, cache=ResultCache(a.cache) if a.cache else None, task_timeout=a.timeout)
    print(json.dumps({"job": a.job, "stats": st, "recovered": q.recovered}))
if __name__ == "__main__": main()
