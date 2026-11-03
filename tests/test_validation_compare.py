import os, shutil, asyncio, pytest
from conftest import LABDATA
from cyberswarm.checks import C
from cyberswarm.agents.validation import validate, fingerprint, normalize_target, proof_status, validate_severity, severity_table_md
from cyberswarm.db import DB
from cyberswarm.report import compare_runs
def F(cid="secret.assignment", target="/x/a.tf", ev="e1", proof=None, agent="cloud", sev=None):
    c = C[cid]; return {"agent": agent, "check_id": cid, "title": c["title"], "severity": sev or c["severity"], "target": target, "evidence": ev,
                        "impact": c["impact"], "recommendation": c["recommendation"], "refs": c["refs"], "proof": proof or {}, "repro": ""}
HTTP = {"type": "http", "request": "GET / HTTP/1.1", "response": "HTTP/1.1 200", "curl": "curl -i x"}
def test_normalize_target():
    assert normalize_target("HTTP://LOCALHOST/") == normalize_target("http://localhost:80")
    assert normalize_target("https://a.test/x/") == "https://a.test:443/x"
    assert normalize_target(os.path.join(LABDATA, "src", "settings.py")) == "labdata/src/settings.py"
def test_fingerprint_stable_and_distinct():
    assert fingerprint(F()) == fingerprint(F()) and fingerprint(F(ev="e1")) != fingerprint(F(ev="e2"))
    assert fingerprint(F(cid="secret.jwt")) != fingerprint(F()) and fingerprint(F(target="/x/b.tf")) != fingerprint(F())
def test_dedupe_keeps_same_title_different_evidence():
    out = validate([F(ev="a", proof=HTTP), F(ev="a", proof=HTTP), F(ev="b", proof=HTTP)])
    assert len(out) == 2 and len({f["fingerprint"] for f in out}) == 2
def test_status_rules(tmp_path):
    from cyberswarm.agents.common import sha
    p = tmp_path / "f.tf"; p.write_text("a\npassword = \"x\"\n")
    good = {"type": "file", "abs": str(p), "line": 2, "line_sha": sha('password = "x"')}
    assert proof_status(good) == "confirmado" and proof_status(HTTP) == "confirmado"
    assert proof_status({"type": "tls", "command": "openssl ...", "observed": "x"}) == "confirmado"
    assert proof_status({}) == "suspeita" and proof_status({"type": "http", "request": "x"}) == "suspeita"
    assert proof_status({**good, "line": 1}) == "suspeita" and proof_status({**good, "line": 99}) == "suspeita"
    p.write_text("changed\n"); assert proof_status(good) == "suspeita"  # file changed -> not reproducible
SEV_CASES = [("secret.aws_key", True, "critical"), ("secret.aws_key", False, "medium"), ("tls.self_signed", True, "high"), ("tls.self_signed", False, "medium"),
             ("web.header.csp", False, "medium"), ("web.header.xfo", True, "low"), ("ios.url_scheme", False, "info")]
@pytest.mark.parametrize("cid,confirmed,expected", SEV_CASES)
def test_severity_table(cid, confirmed, expected):
    f = F(cid, proof=HTTP if confirmed else None, sev="critical")  # wrong incoming severity must be corrected
    assert validate([f])[0]["severity"] == expected
def test_severity_doc_matches_catalog():
    doc = open(os.path.join(os.path.dirname(LABDATA), "..", "docs", "SEVERIDADE.md")).read()
    assert severity_table_md() in doc
def _store(db, fs):
    rid = db.new_run("t")
    for f in validate(fs): db.add_finding(rid, f)
    return rid
def test_compare_new_fixed_persistent_with_same_titles():
    db = DB()
    a = _store(db, [F(ev="senha1", proof=HTTP), F(ev="senha2", proof=HTTP), F("web.header.csp", "http://h", "x", HTTP, "web")])
    b = _store(db, [F(ev="senha2", proof=HTTP), F(ev="senha3", proof=HTTP), F("web.header.csp", "http://h:80/", "x", HTTP, "web")])
    r = compare_runs(db, a, b)
    assert [f["evidence"] for f in r["corrigidos"]] == ["senha1"] and [f["evidence"] for f in r["novos"]] == ["senha3"]
    assert sorted(f["check_id"] for f in r["persistentes"]) == ["secret.assignment", "web.header.csp"]
def test_compare_real_fix_on_client_files(tmp_path):
    """Client copies lab terraform, fixes one secret; compare shows exactly 1 fixed, 0 new."""
    from cyberswarm.scope import Scope
    from cyberswarm.audit import Audit
    from cyberswarm.net import Net
    from cyberswarm.log import get_logger
    from cyberswarm.orchestrator import Ctx, Orchestrator
    d = tmp_path / "tf"; shutil.copytree(os.path.join(LABDATA, "terraform"), d)
    sc = Scope(paths=[str(d)]); au = Audit(str(tmp_path / "a.log")); ctx = Ctx(sc, get_logger("t"), Net(sc, au), au, {}); db = DB()
    r1, f1 = asyncio.run(Orchestrator(ctx, db).run([("cloud", str(d))]))
    t = (d / "main.tf").read_text().replace('  password = "SuperFakeLabPass123"\n', "  password = var.db_password\n")
    (d / "main.tf").write_text("# corrigido\n" + t)  # also shifts every line: fingerprints must survive
    r2, f2 = asyncio.run(Orchestrator(ctx, db).run([("cloud", str(d))]))
    r = compare_runs(db, r1, r2)
    assert len(r["corrigidos"]) == 1 and r["corrigidos"][0]["check_id"] == "secret.assignment" and r["novos"] == [] and len(r["persistentes"]) == len(f1) - 1
    assert all(f["status"] == "confirmado" for f in f2)
