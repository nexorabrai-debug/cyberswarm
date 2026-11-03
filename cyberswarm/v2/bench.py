"""Benchmarks por agente/ferramenta: tempo de parede, CPU (user+sys) e RAM máxima (maxrss) medidos com os.wait4 em
subprocesso isolado (um por medição, então maxrss é do próprio agente). Sem /usr/bin/time (não disponível no box)."""
import json, os, subprocess, sys, tempfile, time
AGENT_SNIPPET = r"""
import asyncio, json, sys
from cyberswarm.scope import Scope
from cyberswarm.audit import Audit
from cyberswarm.net import Net
from cyberswarm.log import get_logger
from cyberswarm.orchestrator import Ctx
from cyberswarm.registry import load_all
agent, target, audit = sys.argv[1:4]
sc = Scope(paths=[target]) if "://" not in target else Scope(hosts=["127.0.0.1"])
au = Audit(audit); c = Ctx(sc, get_logger("bench"), Net(sc, au, max_requests=5000), au, {})
print(json.dumps({"findings": len(asyncio.run(load_all()[agent](c).run(target)))}))
"""
def measure(argv, env=None, timeout=900):
    t0 = time.monotonic()
    p = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, env=env)
    try:
        import threading; out = []
        th = threading.Thread(target=lambda: out.append(p.stdout.read())); th.start()
        deadline = t0 + timeout
        while True:
            pid, status, ru = os.wait4(p.pid, os.WNOHANG)
            if pid: break
            if time.monotonic() > deadline: p.kill()
            time.sleep(0.02)
        th.join(); p.returncode = os.waitstatus_to_exitcode(status)
    finally: p.stdout.close()
    return {"wall_s": round(time.monotonic() - t0, 3), "cpu_s": round(ru.ru_utime + ru.ru_stime, 3),
            "maxrss_mb": round(ru.ru_maxrss / 1024, 1), "rc": p.returncode, "stdout": (out[0] if out else b"").decode(errors="ignore")[-2000:]}
def bench_agent(agent, target):
    with tempfile.TemporaryDirectory() as d:
        r = measure([sys.executable, "-c", AGENT_SNIPPET, agent, target, os.path.join(d, "a.log")],
                    env=dict(os.environ, PYTHONPATH=os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))))
    try: r["findings"] = json.loads(r.pop("stdout").strip().splitlines()[-1])["findings"]
    except Exception: r["findings"] = None
    return {"kind": "agent", "name": agent, "target": target, **r}
def bench_tool(name, argv):
    r = measure(argv); r.pop("stdout"); return {"kind": "tool", "name": name, "argv": " ".join(argv), **r}
