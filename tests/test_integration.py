import json, os, shutil, subprocess
from conftest import free_port
from cyberswarm.cli import main
def _demo(out, cmd="demo", p=None, q=None, extra=()):
    p, q = p or free_port(), q or free_port()
    assert main(["--out", str(out), *extra, cmd, "--port", str(p), "--tls-port", str(q)]) == 0
    return p, q
def _latest(out, ext):
    return sorted(x for x in out.iterdir() if x.suffix == ext)[-1]
def test_demo_all_agents_together(tmp_path):
    _demo(tmp_path, extra=["--no-pdf"])
    d = json.load(open(_latest(tmp_path, ".json")))
    assert {f["agent"] for f in d["findings"]} == {"web", "tls", "api", "cloud", "mobile", "ios", "code"}
    assert all(t["status"] == "done" for t in d["tasks"]) and len(d["tasks"]) == 8
    st = {f["status"] for f in d["findings"]}; assert st == {"confirmado", "suspeita"}
    assert all(f["impact"] and f["recommendation"] and f["evidence"] for f in d["findings"])
    assert all(f["repro"] for f in d["findings"] if f["status"] == "confirmado")
    assert len({f["fingerprint"] for f in d["findings"]}) == len(d["findings"])
def test_compare_two_demo_runs_identical(tmp_path, capsys):
    p, q = _demo(tmp_path, extra=["--no-pdf"]); _demo(tmp_path, p=p, q=q, extra=["--no-pdf"]); capsys.readouterr()
    main(["--out", str(tmp_path), "compare", "1", "2", "--json"]); r = json.loads(capsys.readouterr().out)
    n = len(json.load(open(_latest(tmp_path, ".json")))["findings"])
    assert r["novos"] == [] and r["corrigidos"] == [] and len(r["persistentes"]) == n
    assert main(["--out", str(tmp_path), "audit-verify"]) == 0
def test_scan_cli_lab(tmp_path):
    from cyberswarm.lab import start
    p = free_port(); s = start(p)
    try: assert main(["--out", str(tmp_path), "--no-pdf", "scan", "--target", f"http://127.0.0.1:{p}", "--all"]) == 0
    finally: s.shutdown()
    d = json.load(open(_latest(tmp_path, ".json"))); assert {t["agent"] for t in d["tasks"]} == {"web", "api", "cloud", "mobile", "ios", "code"}
def test_html_responsive_and_escaped(tmp_path):
    from cyberswarm.db import DB
    from cyberswarm.report import write_reports
    from test_validation_compare import F, HTTP, _store
    db = DB(); rid = _store(db, [F(ev="<script>alert(1)</script>", proof=HTTP)])
    h = open(write_reports(db, rid, str(tmp_path), pdf=False)["html"]).read()
    assert 'name="viewport"' in h and "@media (max-width:480px)" in h and 'lang="pt-BR"' in h
    assert "<script>alert" not in h and "&lt;script&gt;" in h and "Suspeita" not in h and "Confirmado" in h
def test_demo_comercial_pdf_html_png(tmp_path):
    import pytest
    _demo(tmp_path, cmd="demo-comercial")
    pdf = _latest(tmp_path, ".pdf"); assert pdf.stat().st_size > 2000 and pdf.read_bytes()[:5] == b"%PDF-"
    if shutil.which("pdftotext"):
        txt = subprocess.run(["pdftotext", str(pdf), "-"], capture_output=True, text=True).stdout
        assert "Relatório de Auditoria de Segurança de Site" in txt and "Certificado autoassinado" in txt and "Como corrigir" in txt
    if shutil.which("pdftoppm"):
        subprocess.run(["pdftoppm", "-png", "-r", "60", "-f", "1", "-l", "1", str(pdf), str(tmp_path / "p")], check=True)
        assert any(x.name.startswith("p") and x.suffix == ".png" for x in tmp_path.iterdir())
    from cyberswarm.report import mobile_screenshot
    png, sw = mobile_screenshot(str(_latest(tmp_path, ".html")), str(tmp_path / "m.png"))
    if png is None: pytest.skip("sem Playwright/Chrome: screenshot não testado")
    assert open(png, "rb").read(4) == b"\x89PNG"
    if sw is not None: assert sw <= 390, f"rolagem lateral no celular: {sw}px"
