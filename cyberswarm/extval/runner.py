"""Run the independent battery against one external lab. Core is reused as-is (Orchestrator, Net, validator, reports)."""
import asyncio, json, os, time, urllib.request
from ..audit import Audit
from ..db import DB
from ..log import get_logger
from ..net import Net
from ..orchestrator import Ctx, Orchestrator
from ..scope import Scope
from ..agents.validation import validate_severity, PRIORITY
from . import probes, apk as _apk, tools_ext  # noqa: F401  (register agents)
from ..agents import labauth as _labauth  # noqa: F401
from .labs import LABS, LABS_DIR, status
from .metrics import evaluate
GENERIC = ["web", "discovery", "graphql", "apidata"]
def jobs_for(lab, mode="1.1", art_dir="/tmp", net=None, use_nuclei=True, use_mobsf=True):
    l = LABS[lab]; j = []
    if l["kind"] == "web":
        u = l["url"]
        if mode == "1.0": return [("web", u), ("network", "tcp://127.0.0.1")]
        j = [(a, u) for a in GENERIC] + [("network", "tcp://127.0.0.1")]
        if lab in ("vampi", "dvga", "juice-shop", "webgoat"): j.append(("labauth", u))
        if lab == "juice-shop":
            src = os.path.join(LABS_DIR, "juice-shop")
            if os.path.isdir(src):
                # lockfile copy com nome aceito pelo osv-scanner
                import shutil
                lock = os.path.join(src, "node_modules", ".package-lock.json")
                dest = os.path.join(art_dir, "package-lock.json")
                if os.path.isfile(lock):
                    shutil.copy2(lock, dest); j.append(("sca", art_dir))
                elif os.path.isfile(os.path.join(src, "package-lock.json")):
                    j.append(("sca", src))
        spec = fetch_spec(u, art_dir, net)
        if spec: j.append(("api", spec))
        if use_nuclei: j.append(("nuclei", u))
    elif l["kind"] == "apk":
        if mode == "1.0": return []
        j = [("apk", l["apk"])] + ([("mobsf", l["apk"])] if use_mobsf else [])
    return j
def fetch_spec(u, art_dir, net):
    from .probes import API_DOCS, _u
    for p in API_DOCS:
        try: st, _, b = net.request(_u(u, p), read=1 << 20)
        except Exception: continue
        if st == 200 and b.lstrip().startswith(b"{") and b'"paths"' in b:
            try: spec = json.loads(b)
            except Exception: continue
            if "openapi" not in spec: continue  # core api agent reads OpenAPI 3
            spec.setdefault("servers", [{"url": u}])
            if not str(spec["servers"][0].get("url", "")).startswith("http"): spec["servers"] = [{"url": u.rstrip("/") + spec["servers"][0].get("url", "")}]
            path = os.path.join(art_dir, "openapi.json"); open(path, "w").write(json.dumps(spec, indent=1)); return path
    return None
def run_lab(lab, out, mode="1.1", workers=6, rate=20, use_nuclei=True, use_mobsf=True, task_timeout=1200, retries=1, extra_opts=None):
    os.makedirs(out, exist_ok=True); art = os.path.join(out, "artifacts"); os.makedirs(art, exist_ok=True)
    l = LABS[lab]; t0 = time.monotonic(); st = status(lab)
    res = {"lab": lab, "mode": mode, "project": l["project"], "status_lab": st}
    if st != "up":
        res["erro"] = l.get("reason") or f"laboratório {lab} fora do ar (porta/arquivo indisponível)"; return res, []
    audit = Audit(os.path.join(out, "audit.log")); log = get_logger("extval")
    scope = Scope(paths=[art, LABS_DIR]); net = Net(scope, audit, rate_per_sec=rate, timeout=5, max_requests=2000)
    opts = {"ports": [l["port"]] if l.get("port") else [], "tools": {"network": "nmap"}, "artifacts_dir": art, **(extra_opts or {})}
    ctx = Ctx(scope, log, net, audit, opts)
    tasks = []
    orch = Orchestrator(ctx, DB(os.path.join(out, "cyberswarm.db")), workers=workers, task_timeout=task_timeout, retries=retries,
                        on_task=lambda n, tg, s, k, secs, att: tasks.append({"agente": n, "alvo": tg, "status": s, "achados": k, "segundos": round(secs, 2), "tentativas": att}))
    jobs = jobs_for(lab, mode, art, net, use_nuclei, use_mobsf)
    _, findings = asyncio.run(orch.run(jobs, label=f"extval-{lab}-{mode}"))
    n_corr = tools_ext.corroborate(findings)
    for f in findings: f["severity"] = validate_severity(f); f["priority"] = PRIORITY[f["severity"]]
    m = evaluate(lab, findings)
    res.update(metricas=m, tarefas=tasks, segundos=round(time.monotonic() - t0, 2), mobsf_corroborados=n_corr,
               tool_stats=ctx.options.get("tool_stats", {}), tool_used=ctx.options.get("tool_used", {}), requisicoes=net.count)
    json.dump({"resultado": res, "achados": findings}, open(os.path.join(out, f"extval_{lab}_{mode}.json"), "w"), indent=1, ensure_ascii=False, default=str)
    return res, findings
