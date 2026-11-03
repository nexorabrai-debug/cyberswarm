"""Etapa C (2.0): fila persistente + retomada após SIGKILL, cache, modo determinístico, adaptador, confiança, bench, SCA."""
import json, os, signal, sqlite3, subprocess, sys, time, shutil
import pytest
from cyberswarm.audit import Audit
from cyberswarm.v2 import cache as C, confidence, deterministic as D, model, bench
from cyberswarm.v2.queue import PersistentQueue
from cyberswarm.scope import LABDATA
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PLUGIN = '''
import asyncio, os
from cyberswarm.registry import Agent, register
@register
class Sleepy(Agent):
    name = "sleepy"; kind = "path"
    async def run(self, target):
        open(os.environ["V2_TRACE"], "a").write(target + "\\n")
        await asyncio.sleep(float(os.environ.get("V2_SLEEP", "0.4")))
        return [{"agent": "sleepy", "check_id": "x", "target": target, "title": "t", "severity": "info", "proof": {}}]
'''
def _cmd(tmp, n=8, cache=False):
    c = [sys.executable, "-m", "cyberswarm.v2.run", "--db", str(tmp / "q.db"), "--job", "J", "--plugin", str(tmp / "p.py"), "--path", str(tmp)]
    c += sum([["--task", f"sleepy={tmp}/t{i}"] for i in range(n)], [])
    if cache: c += ["--cache", str(tmp / "c.db")]
    return c
def test_resume_after_sigkill(tmp_path):
    (tmp_path / "p.py").write_text(PLUGIN)
    for i in range(8): (tmp_path / f"t{i}").write_text("x")
    env = dict(os.environ, PYTHONPATH=ROOT, V2_TRACE=str(tmp_path / "trace"))
    p = subprocess.Popen(_cmd(tmp_path), env=env, cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    deadline = time.time() + 30
    while time.time() < deadline:  # matar no meio: depois de >=2 checkpoints e antes do fim
        if (tmp_path / "q.db").exists():
            try: done = sqlite3.connect(tmp_path / "q.db").execute("SELECT COUNT(*) FROM q WHERE status='done'").fetchone()[0]
            except sqlite3.OperationalError: done = 0
            if done >= 2: break
        time.sleep(0.05)
    os.kill(p.pid, signal.SIGKILL); p.wait()
    db = sqlite3.connect(tmp_path / "q.db")
    before = dict(db.execute("SELECT status, COUNT(*) FROM q GROUP BY status").fetchall())
    assert before.get("done", 0) >= 2 and before.get("done", 0) < 8
    done_before = {r[0] for r in db.execute("SELECT target FROM q WHERE status='done'")}
    out = subprocess.run(_cmd(tmp_path), env=env, cwd=ROOT, capture_output=True, text=True, timeout=60)
    res = json.loads(out.stdout.strip().splitlines()[-1])
    assert res["stats"] == {"done": 8}
    trace = (tmp_path / "trace").read_text().split()
    # tarefas com checkpoint não são reexecutadas; no máximo a tarefa em andamento no kill roda duas vezes
    assert all(trace.count(t) == 1 for t in done_before)
    assert len(trace) - 8 <= 1
    q = PersistentQueue(str(tmp_path / "q.db")); assert len(q.findings("J")) == 8
def test_cache_hit_and_invalidation(tmp_path):
    (tmp_path / "p.py").write_text(PLUGIN)
    for i in range(3): (tmp_path / f"t{i}").write_text("x")
    env = dict(os.environ, PYTHONPATH=ROOT, V2_TRACE=str(tmp_path / "trace"), V2_SLEEP="0")
    run = lambda job: subprocess.run([*_cmd(tmp_path, 3, cache=True)[:6], job, *_cmd(tmp_path, 3, cache=True)[7:]], env=env, cwd=ROOT, capture_output=True, timeout=60)
    run("A"); run("B")
    assert len((tmp_path / "trace").read_text().split()) == 3  # job B veio todo do cache
    time.sleep(0.01); (tmp_path / "t1").write_text("mudou")
    run("C"); assert (tmp_path / "trace").read_text().split().count(f"{tmp_path}/t1") == 2
    rc = C.ResultCache(str(tmp_path / "c2.db")); assert rc.key("web", "http://127.0.0.1:3000") is None  # URL sem TTL não cacheia
def _plan():
    from cyberswarm.hacker.planner import plan
    return plan("testar api e web do laboratório", {"url": "http://127.0.0.1:3000", "openapi": os.path.join(LABDATA, "openapi.json")})
def test_deterministic_gate(tmp_path):
    au = Audit(str(tmp_path / "a.log")); g = D.DeterministicGate(str(tmp_path / "plans.json"), au)
    p1, p2 = _plan(), _plan(); t1 = p1["tasks"] if isinstance(p1, dict) else p1; t2 = p2["tasks"] if isinstance(p2, dict) else p2
    assert D.plan_hash(t1) == D.plan_hash(t2)  # determinístico
    passive = [t for t in t1 if not t.get("active") and t.get("agent") != "exploitlab"]
    assert g.check(passive)[0] is True
    ok, why, h = g.check(t1); assert D.is_complex(t1) and ok is False and "pré-aprovado" in why
    (tmp_path / "plans.json").write_text(json.dumps({"plans": [{"plan_sha256": h, "approved_by": "dono", "expires": time.time() + 60}]}))
    assert g.check(t1)[0] is True
    t1[0]["target"] = "http://127.0.0.1:9999"; assert g.check(t1)[0] is False  # plano alterado = novo hash
    (tmp_path / "plans.json").write_text(json.dumps({"plans": [{"plan_sha256": h, "approved_by": "dono", "expires": time.time() - 1}]}))
    assert g.check(t2)[0] is False  # expirado
    assert "deterministic_gate" in (tmp_path / "a.log").read_text()
def test_model_adapter_off_by_default(monkeypatch):
    monkeypatch.delenv("CYBERSWARM_MODEL", raising=False)
    a = model.get_adapter(); assert a.name == "off" and a.suggest_modules("x", ["web"]) == []
    monkeypatch.setenv("CYBERSWARM_MODEL", "ollama")
    assert model.get_adapter(deterministic=True).name == "off"
    monkeypatch.setenv("OLLAMA_URL", "http://evil.example"); assert model.get_adapter().suggest_modules("web", ["web"]) == []
def test_confidence_and_contradictions():
    fp = {"type": "file", "path": "a", "line": 1}
    fs = [{"agent": "code", "check_id": "c1", "target": "t", "status": "confirmado", "severity": "high", "proof": fp, "corroborated_by": ["mobsf"]},
          {"agent": "nuclei", "check_id": "c2", "target": "u", "status": "suspeita", "severity": "medium", "proof": {}, "tool": "nuclei"},
          {"agent": "web", "check_id": "c3", "target": "v", "status": "confirmado", "severity": "high", "proof": {"type": "http"}},
          {"agent": "zap", "check_id": "c3", "target": "v", "status": "refutado", "severity": "low", "proof": {}}]
    con = confidence.contradictions(fs); types = {c["type"] for c in con}
    assert {"status", "severidade"} <= types
    confidence.score(fs)
    assert fs[0]["confidence_band"] == "alta" and fs[1]["confidence_band"] == "baixa" and fs[2]["confidence"] < 75
def test_bench_measures_cpu_ram():
    r = bench.bench_agent("code", os.path.join(LABDATA, "src"))
    assert r["rc"] == 0 and r["findings"] and r["findings"] > 0 and r["wall_s"] > 0 and r["maxrss_mb"] > 5 and r["cpu_s"] >= 0
    t = bench.bench_tool("python", [sys.executable, "-c", "x=bytearray(60*2**20); sum(range(10**6))"])
    assert t["maxrss_mb"] >= 60 and t["cpu_s"] > 0
def test_sca_agent_with_fake_tool(tmp_path, monkeypatch):
    lock = tmp_path / "package-lock.json"
    lock.write_text(json.dumps({"packages": {"node_modules/sanitize-html": {"version": "1.4.2"}, "node_modules/ok": {"version": "1.0.0"}}}, indent=2))
    bin_ = tmp_path / "bin"; bin_.mkdir(); f = bin_ / "osv-scanner"
    f.write_text("#!/bin/sh\necho '" + json.dumps({"results": [{"packages": [
        {"package": {"name": "sanitize-html", "version": "1.4.2"}, "vulnerabilities": [{"id": "GHSA-xxxx"}]},
        {"package": {"name": "fantasma", "version": "9.9.9"}, "vulnerabilities": [{"id": "GHSA-yyyy"}]}]}]}) + "'\n"); f.chmod(0o755)
    monkeypatch.setenv("CYBERSWARM_TOOLBIN", str(bin_)); monkeypatch.setenv("HOME", str(tmp_path))
    import asyncio
    from cyberswarm.scope import Scope; from cyberswarm.net import Net; from cyberswarm.log import get_logger
    from cyberswarm.orchestrator import Ctx; from cyberswarm.registry import load_all; from cyberswarm.agents.validation import validate
    sc = Scope(paths=[str(tmp_path)]); au = Audit(str(tmp_path / "a.log"))
    fs = validate(asyncio.run(load_all()["sca"](Ctx(sc, get_logger("t"), Net(sc, au), au, {})).run(str(tmp_path))))
    assert len(fs) == 1 and "sanitize-html@1.4.2" in fs[0]["title"] and fs[0]["status"] == "confirmado"  # fantasma sem prova no arquivo -> descartado
    assert '"online": true' in (tmp_path / "a.log").read_text() or "online" in (tmp_path / "a.log").read_text()
def test_sca_no_tool_no_findings(tmp_path, monkeypatch):
    (tmp_path / "package-lock.json").write_text("{}")
    monkeypatch.setenv("CYBERSWARM_DISABLE_TOOLS", "osv-scanner,trivy,grype")
    import asyncio
    from cyberswarm.scope import Scope; from cyberswarm.net import Net; from cyberswarm.log import get_logger
    from cyberswarm.orchestrator import Ctx; from cyberswarm.registry import load_all
    sc = Scope(paths=[str(tmp_path)]); au = Audit(str(tmp_path / "a.log"))
    assert asyncio.run(load_all()["sca"](Ctx(sc, get_logger("t"), Net(sc, au), au, {})).run(str(tmp_path))) == []
