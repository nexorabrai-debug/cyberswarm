"""Hacker AI 1.0: one test group per capability."""
import asyncio, datetime, json, os, shutil, stat
import pytest
from conftest import free_port, T
from cyberswarm.scope import Scope, LABDATA
from cyberswarm.audit import Audit, verify as audit_verify
from cyberswarm.db import DB
from cyberswarm.orchestrator import Orchestrator, Ctx, PartialResult
from cyberswarm.registry import Agent, register, load_all
from cyberswarm.hacker import planner, selector
from cyberswarm.hacker.memory import Memory
from cyberswarm.hacker.bus import Bus, validate_message, InvalidMessage, SCHEMA
from cyberswarm.hacker.approvals import ApprovalGate
from cyberswarm.hacker.metrics import evaluate, load_gt
from cyberswarm.hacker.verify import verify_all
from cyberswarm.hacker.engine import HackerAI, lab_targets
from cyberswarm.hacker.intel import threat_intel, vuln_research
from cyberswarm.agents.validation import validate
from cyberswarm.tools import which
LT = lambda: lab_targets("http://127.0.0.1:1", "https://127.0.0.1:2")
# ---------- planner ----------
def test_planner_full_lab_dag():
    P = planner.plan("auditar laboratório completo", LT())
    assert set(P["modules"]) == set(planner.MODULES)
    by = {t["module"]: t for t in P["tasks"]}
    ex = by["exploitlab"]; web_ids = [t["id"] for t in P["tasks"] if t["module"] == "web" and t["target"].startswith("http://")]
    assert ex["deps"] == web_ids and ex["condition"]
    ver = by["verification"]; scans = [t["id"] for t in P["tasks"] if t["kind"] == "scan"]
    assert set(ver["deps"]) == set(scans)
    order = [t for l in P["levels"] for t in l]
    for t in P["tasks"]:
        for d in t["deps"]: assert order.index(d) < order.index(t["id"])
    assert planner.plan("auditar laboratório completo", LT()) == P  # deterministic
def test_planner_keywords_and_skip():
    P = planner.plan("revisar a API e os prompts de IA", LT())
    assert set(P["modules"]) == {"api", "aisec"}
    P = planner.plan("auditar rede e código", {"url": "https://cliente.example"}, lab=False)
    assert ("network", "sem alvo 'tcp'") in P["skipped"] and "metrics" not in [t["module"] for t in P["tasks"]]
    P = planner.plan("exploit poc", {"url": "https://cliente.example"}, lab=False)
    assert "exploitlab" not in [t["module"] for t in P["tasks"]]
def test_planner_yaml_json_and_cycles(tmp_path):
    y = tmp_path / "goal.yaml"; y.write_text("goal: revisar nuvem\nmodules:\n  - cloud\n  - aisec\n")
    assert planner.plan(str(y), LT())["modules"] == ["cloud", "aisec"]
    assert planner._mini_yaml("goal: x\nmodules: [cloud, ios]\n")["modules"] == ["cloud", "ios"]
    assert planner.plan('{"goal":"x","modules":["ios"]}', LT())["modules"] == ["ios"]
    with pytest.raises(ValueError): planner.levels([{"id": "A", "deps": ["B"]}, {"id": "B", "deps": ["A"]}])
def test_llm_hook_off_by_default_and_graceful(monkeypatch):
    monkeypatch.delenv("CYBERSWARM_LLM", raising=False); assert planner.llm_suggest("tudo") == []
    monkeypatch.setenv("CYBERSWARM_LLM", "ollama")
    monkeypatch.setattr("urllib.request.urlopen", lambda *a, **k: (_ for _ in ()).throw(OSError("sem ollama")))
    assert planner.llm_suggest("tudo") == []
    class R:
        def read(self): return json.dumps({"response": "web, rm -rf, network, foo"}).encode()
    monkeypatch.setattr("urllib.request.urlopen", lambda *a, **k: R())
    assert planner.llm_suggest("x") == ["web", "network"]  # only known modules
# ---------- memory ----------
def test_memory_persists_across_runs(tmp_path):
    out = str(tmp_path / "o")
    s1 = HackerAI(out).run("auditar código", LT(), pdf=False)
    s2 = HackerAI(out).run("auditar código", LT(), pdf=False)  # new process-like instance, same db file
    assert s1["new"] == s1["findings"] > 0 and s2["recurring"] == s2["findings"] and s2["new"] == 0
    m = Memory(os.path.join(out, "hacker_memory.db")); assert len(m.runs()) == 2
    st = m.tool_stats(s2["tool_used"]["codesec"], "codesec"); assert st["runs"] == 2 and st["tp"] > 0
    assert m.history(s2["findings_list"][0]["fingerprint"])["times_seen"] == 2
    assert m.messages(2) and "treinamento" in open(os.path.join(os.path.dirname(selector.__file__), "memory.py")).read()
# ---------- selector ----------
def test_selector_fallback_when_tools_missing(monkeypatch):
    monkeypatch.setenv("CYBERSWARM_DISABLE_TOOLS", "semgrep,bandit,nmap")
    assert selector.select("codesec", "code")["tool"] == "builtin"
    assert selector.select("network", "tcp")["tool"] == "builtin"
    r = selector.select("codesec", "code"); assert [x for x in r["ranking"] if x["tool"] == "semgrep"][0]["why"] == "não instalado"
    assert selector.select("web", "url")["tool"] == "builtin"
def test_selector_uses_memory(monkeypatch, tmp_path):
    monkeypatch.setattr(selector, "available", lambda exe: True)
    m = Memory(str(tmp_path / "m.db"))
    for _ in range(3): m.record_tool("semgrep", "codesec", False, 60)  # always failing and slow
    m.record_tool("bandit", "codesec", True, 0.2); m.record_quality("bandit", "codesec", 8, 0)
    assert selector.select("codesec", "code", m)["tool"] == "bandit"
def test_runtime_tool_failure_falls_back(tmp_path, monkeypatch, ctx):
    fake = tmp_path / "bin"; fake.mkdir(); b = fake / "bandit"; b.write_text("#!/bin/sh\necho broken >&2\nexit 2\n"); b.chmod(0o755)
    monkeypatch.setenv("CYBERSWARM_TOOLBIN", str(fake)); ctx.options["tools"] = {"codesec": "bandit"}
    fs = asyncio.run(load_all()["codesec"](ctx).run(os.path.join(LABDATA, "src")))
    assert ctx.options["tool_used"]["codesec"] == "builtin" and len(fs) == 8
    assert "tool_fallback" in open(ctx.audit.path).read()
# ---------- approval gate ----------
def _gate(tmp_path, approvals):
    p = tmp_path / "approvals.json"; p.write_text(json.dumps({"approvals": approvals})); a = Audit(str(tmp_path / "audit.log"))
    return ApprovalGate(str(p), a), a
def test_approval_gate_denies_by_default(tmp_path):
    tomorrow = (datetime.date.today() + datetime.timedelta(days=1)).isoformat(); yesterday = (datetime.date.today() - datetime.timedelta(days=1)).isoformat()
    g, a = _gate(tmp_path, [{"token": "OK1", "op": "active_client_test", "target": "https://cliente.example", "approved_by": "Renato", "expires": tomorrow},
                            {"token": "OLD", "op": "active_client_test", "target": "https://cliente.example", "approved_by": "Renato", "expires": yesterday},
                            {"token": "NOBODY", "op": "active_client_test", "target": "https://cliente.example", "expires": tomorrow}])
    t = "https://cliente.example/login"
    assert not g.check("active_client_test", t)                      # no token
    assert not g.check("active_client_test", t, "NOPE")              # unknown token
    assert not g.check("active_client_test", t, "OLD")               # expired
    assert not g.check("active_client_test", t, "NOBODY")            # no approver
    assert not g.check("system_change", t, "OK1")                    # wrong op
    assert not g.check("active_client_test", "https://outro.example", "OK1")  # wrong target
    assert not g.check("out_of_scope", t, "OK1")                     # never
    assert g.check("active_client_test", t, "OK1")
    log = open(a.path).read(); assert log.count("approval_denied") == 7 and log.count("approval_granted") == 1
    assert audit_verify(a.path)[0]
def test_engine_denies_active_client_tests_without_approval(tmp_path):
    out = str(tmp_path / "o"); hk = HackerAI(out, str(tmp_path / "none.json"))
    sc = Scope(hosts=["cliente.example"], client={"name": "Cliente", "authorization_ref": "X"})
    s = hk.run("auditar site", {"url": "https://cliente.example"}, sc, "c1", None, pdf=False)
    assert s["denied"] and s["findings"] == 0 and not [p for p in s["perf"]]
    log = open(os.path.join(out, "audit.log")).read(); assert "approval_denied" in log and '"op": "http"' not in log
def test_install_tools_requires_approval(tmp_path):
    from cyberswarm.cli import main
    assert main(["--out", str(tmp_path), "hacker", "install-tools", "--approvals", str(tmp_path / "x.json")]) == 3
    assert "system_change" in open(tmp_path / "audit.log").read()
# ---------- verification + hypotheses ----------
def test_verification_reproduces_and_downgrades(tmp_path, ctx):
    from cyberswarm.lab import start
    p = free_port(); srv = start(p); url = f"http://127.0.0.1:{p}"
    fs = validate(asyncio.run(load_all()["web"](ctx).run(url)))
    for f in fs: f["task_target"] = url
    s = verify_all(fs, load_all(), lambda: ctx, {}); assert s["reproduced"] == s["checked"] == len(fs) and s["downgraded"] == 0
    srv.shutdown(); srv.server_close()
    s = verify_all(fs, load_all(), lambda: ctx, {})
    assert s["downgraded"] == len(fs) and all(f["status"] == "suspeita" for f in fs)
    assert all(f["severity"] in ("info", "low", "medium") for f in fs)  # suspeita capped
def test_verification_detects_changed_file(tmp_path):
    src = tmp_path / "src"; shutil.copytree(os.path.join(LABDATA, "src"), src)
    sc = Scope(paths=[str(tmp_path)]); au = Audit(str(tmp_path / "a.log"))
    from cyberswarm.net import Net; from cyberswarm.log import get_logger
    c = Ctx(sc, get_logger("t"), Net(sc, au), au, {"tools": {"codesec": "builtin"}})
    fs = validate(asyncio.run(load_all()["codesec"](c).run(str(src))))
    for f in fs: f["task_target"] = str(src)
    app = src / "app.py"; app.write_text(app.read_text().replace("return eval(expr)", "return int(expr)"))
    s = verify_all(fs, load_all(), lambda: c, {"codesec": "builtin"})
    ev = [f for f in fs if f["check_id"] == "codesec.eval"][0]
    assert ev["status"] == "suspeita" and ev["verification"]["reproduced"] is False and s["downgraded"] == 1
def test_hypotheses_reevaluated_across_runs(tmp_path):
    out = str(tmp_path / "o"); man = tmp_path / "android"; shutil.copytree(os.path.join(LABDATA, "android"), man)
    sc = Scope(paths=[str(tmp_path)]); goal = {"goal": "android", "modules": ["android"]}; t = {"manifest": str(man)}
    s1 = HackerAI(out).run(goal, t, sc, pdf=False)
    h1 = [h for h in s1["hypotheses"] if h["key"].startswith("fp:")]; assert len(h1) == 1 and h1[0]["status"] == "aberta"  # allowBackup implicit
    HackerAI(out).run({"goal": "ios", "modules": ["ios"]}, LT(), pdf=False)  # android not run: hypothesis stays open
    m = Memory(os.path.join(out, "hacker_memory.db")); st = lambda: [h for h in m.hypotheses() if h["id"] == h1[0]["id"]][0]["status"]
    assert st() == "aberta"
    x = man / "AndroidManifest.xml"; x.write_text(x.read_text().replace("<application ", '<application android:allowBackup="false" '))
    HackerAI(out).run(goal, t, sc, pdf=False); assert st() == "descartada"
# ---------- recovery ----------
CALLS = {"n": 0}
@register
class Flaky(Agent):
    name = "_flaky"; kind = "path"
    async def run(self, target):
        CALLS["n"] += 1
        if CALLS["n"] == 1: raise ConnectionError("falha transitória")
        return [self.finding("net.open.other", target, "ok", {"type": "tcp", "command": "x", "observed": "y"})]
@register
class Slow(Agent):
    name = "_slow"; kind = "path"
    async def run(self, target): await asyncio.sleep(5); return []
@register
class Half(Agent):
    name = "_half"; kind = "path"
    async def run(self, target): raise PartialResult([self.finding("net.open.other", target, "parcial", {"type": "tcp", "command": "x", "observed": "y"})], "orçamento esgotado")
def test_recovery_retry_timeout_partial(ctx):
    db = DB(); seen = []
    o = Orchestrator(ctx, db, task_timeout=0.5, retries=1, backoff=0.01, on_task=lambda *a: seen.append(a))
    rid, fs = asyncio.run(o.run([("_flaky", LABDATA), ("_slow", LABDATA), ("_half", os.path.join(LABDATA, "ios"))]))
    st = {t["agent"]: t["status"] for t in db.tasks(rid)}
    assert st == {"_flaky": "done", "_slow": "error", "_half": "partial"}
    assert {f["evidence"] for f in fs} == {"ok", "parcial"}
    assert [a for a in seen if a[0] == "_flaky"][0][5] == 2 and "task_retry" in open(ctx.audit.path).read()
# ---------- metrics ----------
def test_metrics_precision_recall():
    gt = [{"module": "m", "check_id": "a", "target": "http://h/", "match": ""}, {"module": "m", "check_id": "b", "target": "http://h/", "match": "x1"},
          {"module": "m", "check_id": "c", "target": "http://h/", "match": ""}, {"module": "z", "check_id": "d", "target": "http://h/", "match": ""}]
    fs = [{"agent": "m", "check_id": "a", "target": "http://h", "title": "", "evidence": ""}, {"agent": "m", "check_id": "b", "target": "http://h/", "title": "t", "evidence": "x1"},
          {"agent": "m", "check_id": "b", "target": "http://h/", "title": "t", "evidence": "x2"}]
    r = evaluate(fs, gt, {"m"})
    assert (r["tp"], r["fp"], r["fn"]) == (2, 1, 1) and r["precision"] == r["recall"] == 0.6667
    assert len(load_gt(subst={"http": "1", "https": "2", "tcp_http": "tcp://127.0.0.1:1", "tcp_https": "tcp://127.0.0.1:2"})) >= 80
# ---------- bus ----------
def test_bus_schema_and_delivery(tmp_path):
    m = Memory(str(tmp_path / "m.db")); b = Bus(7, m); got = []
    b.subscribe("finding", got.append); b.publish("finding", "web", {"fingerprint": "f"}); b.publish("task", "planner", {"t": 1}, "web")
    assert len(got) == 1 and len(m.messages(7)) == 2
    for bad in ({"id": 1}, {**b.log[0], "type": "hack"}, {**b.log[0], "extra": 1}, {**b.log[0], "payload": "x"}):
        with pytest.raises(InvalidMessage): validate_message(bad)
    assert set(SCHEMA["required"]) == set(b.log[0])
    doc = open(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "docs", "INTERFACES.md")).read()
    for f in SCHEMA["required"]: assert f"`{f}`" in doc
# ---------- new modules ----------
def test_codesec_builtin_and_negatives(run_agent, ctx):
    ctx.options["tools"] = {"codesec": "builtin"}; fs = run_agent("codesec", os.path.join(LABDATA, "src"), ctx)
    assert sorted(T(fs)) == sorted(["codesec.eval", "codesec.shell", "codesec.pickle", "codesec.yaml_load", "codesec.weak_hash", "codesec.tls_verify_off", "codesec.sql_concat", "codesec.debug"])
    assert all(int(f["evidence"].split()[1]) < 26 or f["check_id"] == "codesec.debug" for f in fs)  # safe_examples (l.26-30) not flagged
@pytest.mark.parametrize("tool", ["semgrep", "bandit"])
def test_codesec_external_tools(run_agent, ctx, tool):
    if not which(tool): pytest.skip(f"{tool} não instalado")
    ctx.options["tools"] = {"codesec": tool}; fs = run_agent("codesec", os.path.join(LABDATA, "src"), ctx)
    assert ctx.options["tool_used"]["codesec"] == tool and {"codesec.eval", "codesec.shell", "codesec.pickle"} <= set(T(fs))
def test_network_lab_only(run_agent, ctx):
    from cyberswarm.lab import start
    with pytest.raises(PermissionError): run_agent("network", "tcp://10.0.0.1")
    p = free_port(); srv = start(p); ctx.options["ports"] = [p, free_port()]
    try: fs = run_agent("network", "tcp://127.0.0.1", ctx)
    finally: srv.shutdown(); srv.server_close()
    assert [(f["check_id"], f["target"]) for f in fs] == [("net.open.cleartext", f"tcp://127.0.0.1:{p}")]
def test_aisec(run_agent):
    fs = run_agent("aisec", os.path.join(LABDATA, "ai"))
    assert sorted(T(fs)) == sorted(["ai.secret_in_prompt", "ai.prompt_injection", "ai.system_prompt_disclosure", "ai.dangerous_tool", "ai.no_output_filter"])
    assert not [f for f in fs if "safe_prompt" in f["target"]] and all("sk-lab" not in json.dumps(f) for f in fs)
def test_exploitlab_hard_locked_and_poc(run_agent, lab_url):
    for t in ("https://example.com", "http://localhost:1", "http://10.0.0.5"):
        with pytest.raises(PermissionError): run_agent("exploitlab", t)
    fs = run_agent("exploitlab", lab_url)
    assert sorted(T(fs)) == ["poc.cors_creds", "poc.env_exposure", "poc.git_exposure"]
    env = [f for f in fs if f["check_id"] == "poc.env_exposure"][0]
    assert "fake_lab_password" not in json.dumps(env) and "2/2" in env["evidence"]
def test_threat_intel_and_research():
    fs = [{"check_id": "web.exposed.env", "refs": ["CWE-538"], "evidence": "", "status": "confirmado"},
          {"check_id": "web.server_version", "refs": ["CWE-200"], "evidence": "Server: Apache/2.4.49", "status": "confirmado"},
          {"check_id": "ai.prompt_injection", "refs": ["OWASP-LLM01"], "evidence": "", "status": "suspeita"}]
    assert threat_intel(fs) == 3
    assert "T1552.001 Credentials In Files" in fs[0]["intel"]["attack"] and fs[1]["intel"]["cves"][0]["cve"] == "CVE-2021-41773"
    ch = vuln_research(fs); assert [c["name"] for c in ch] == ["Vazamento de credenciais por arquivo exposto"]  # suspeita does not form chains
    assert "hipótese" in fs[2]["research"]
# ---------- end-to-end ----------
def test_hacker_cli_demo_end_to_end(tmp_path):
    from cyberswarm.cli import main
    out = tmp_path / "r"; hp, tp = free_port(), free_port()
    assert main(["--out", str(out), "hacker", "demo", "--port", str(hp), "--tls-port", str(tp)]) == 0
    hj = json.load(open(next(out.glob("hacker-*.json"))))
    m = hj["metrics"]; assert m["recall"] >= 0.95 and m["precision"] >= 0.95
    assert hj["verification"]["checked"] > 50 and hj["verification"]["downgraded"] == 0
    assert len(hj["plan"]["tasks"]) == 17 and hj["chains"]
    assert list(out.glob("report-*.pdf")) and audit_verify(str(out / "audit.log"))[0]
    assert main(["--out", str(out), "--no-pdf", "hacker", "--goal", "auditar laboratório completo", "--port", str(hp), "--tls-port", str(tp)]) == 0
    assert len(Memory(str(out / "hacker_memory.db")).runs()) == 2
