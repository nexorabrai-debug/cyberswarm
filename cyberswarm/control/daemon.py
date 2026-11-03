"""Worker daemon independente do processo HTTP.
Uso: cyberswarm worker --data DIR
Continua processando a fila mesmo se o navegador/PWA fechar. Sem systemd (loop + sleep).
Vários daemons no mesmo DB: claim otimista via UPDATE ... WHERE status='na_fila'."""
import argparse, os, signal, sys, time
from ..audit import Audit
from ..log import get_logger
from .store import Store
from .worker import Worker, MAX_CONCURRENT
def main(argv=None):
    ap = argparse.ArgumentParser(prog="cyberswarm-worker")
    ap.add_argument("--data", default=os.path.expanduser("~/cs-control"))
    ap.add_argument("--poll", type=float, default=1.0)
    ap.add_argument("--once", action="store_true", help="processa no máximo um job e sai (testes)")
    a = ap.parse_args(argv)
    os.makedirs(a.data, exist_ok=True)
    log = get_logger("worker"); audit = Audit(os.path.join(a.data, "control_audit.log"))
    store = Store(os.path.join(a.data, "control.db"))
    w = Worker(store, a.data, audit, workers=0, autostart=False)
    stop = {"v": False}
    signal.signal(signal.SIGTERM, lambda *_: stop.__setitem__("v", True))
    signal.signal(signal.SIGINT, lambda *_: stop.__setitem__("v", True))
    audit.log("worker_daemon_start", pid=os.getpid(), max_concurrent=MAX_CONCURRENT)
    log.info(f"worker daemon pid={os.getpid()} data={a.data}")
    # re-enfileira na_fila (já feito no __init__ para executando→na_fila)
    while not stop["v"]:
        jid = w.claim_next()
        if jid is None:
            if a.once: break
            time.sleep(a.poll); continue
        try: w.run_job(jid)
        except Exception as e: log.error(f"job {jid}: {e!r}")
        if a.once: break
    audit.log("worker_daemon_stop", pid=os.getpid()); return 0
if __name__ == "__main__": sys.exit(main())
