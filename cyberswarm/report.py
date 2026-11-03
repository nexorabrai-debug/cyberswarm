"""Reports: JSON, Markdown, responsive pt-BR HTML, PDF (fpdf2, fallback headless Chrome), mobile screenshot, comparison."""
from .agents.common import display_path
import html, json, os, shutil, subprocess, tempfile, time
SEV = ["info", "low", "medium", "high", "critical"]
SEV_PT = {"critical": "Crítico", "high": "Alto", "medium": "Médio", "low": "Baixo", "info": "Informativo"}
COLORS = {"critical": "#6a1b9a", "high": "#c62828", "medium": "#ef6c00", "low": "#1565c0", "info": "#546e7a"}
def _proof_text(p):
    if not p: return "Sem evidência reproduzível (classificado como suspeita)."
    if p["type"] == "http": return f"$ {p['curl']}\n\n--- requisição ---\n{p['request']}\n\n--- resposta ---\n{p['response']}"
    if p["type"] in ("tls", "tcp"): return f"$ {p['command']}\n\n--- observado ---\n{p['observed']}"
    if p["type"] == "file": return f"{p['path']}:{p['line']}\n{p['snippet']}"
    return json.dumps(p, ensure_ascii=False)
def _where(t): return t if "://" in t else display_path(t)
def counts(fs): return {s: sum(1 for x in fs if x["severity"] == s) for s in SEV}
def write_reports(db, rid, outdir, meta=None, pdf=True, extra=None):
    """extra: optional [(section_title, [lines])] appended by Hacker AI (plan, tools, verification, metrics...)."""
    os.makedirs(outdir, exist_ok=True); meta = meta or {}
    fs = db.findings(rid); fs.sort(key=lambda f: (-SEV.index(f["severity"]), f["status"] != "confirmado", f["agent"], f["title"]))
    tasks = db.tasks(rid); stamp = time.strftime("%Y%m%d-%H%M%S"); base = os.path.join(outdir, f"report-{rid}-{stamp}")
    cnt = counts(fs)
    with open(base + ".json", "w") as f:
        json.dump({"run_id": rid, "meta": meta, "counts": cnt, "tasks": tasks, "findings": [{k: v for k, v in x.items() if k != "id"} for x in fs]}, f, indent=2, ensure_ascii=False)
    L = [f"# Relatório CyberSwarm — análise {rid}", "", f"Cliente: {meta.get('client_name', 'Laboratório')}", "",
         " | ".join(f"{SEV_PT[k]}: {v}" for k, v in reversed(cnt.items())),
         f"Confirmados: {sum(x['status']=='confirmado' for x in fs)} | Suspeitas: {sum(x['status']=='suspeita' for x in fs)}", "",
         "| agente | alvo | status |", "|---|---|---|"] + [f"| {t['agent']} | {t['target']} | {t['status']} {t['error'] or ''} |" for t in tasks] + [""]
    for i, x in enumerate(fs, 1):
        L += [f"## {i}. [{x['severity'].upper()} · {x['status']}] {x['title']}", f"- Agente/checagem: {x['agent']} / `{x['check_id']}` (fingerprint `{x['fingerprint']}`)",
              f"- Alvo: `{_where(x['target'])}`", f"- Impacto: {x['impact']}", f"- Evidência: {x['evidence']}", f"- Como reproduzir: {x['repro'] or '-'}",
              f"- Correção: {x['recommendation']}", f"- Referências: {', '.join(x['refs'])}", "", "```", _proof_text(x["proof"]), "```", ""]
    for title, lines in extra or []: L += [f"## {title}", ""] + [f"- {x}" for x in lines] + [""]
    open(base + ".md", "w").write("\n".join(L))
    open(base + ".html", "w").write(render_html(rid, fs, cnt, meta, extra))
    out = {"md": base + ".md", "json": base + ".json", "html": base + ".html", "pdf": None, "counts": cnt}
    if pdf: out["pdf"] = export_pdf(rid, fs, cnt, meta, base + ".pdf", base + ".html", extra)
    return out
def render_html(rid, fs, cnt, meta, extra=None):
    e = html.escape; conf = sum(x["status"] == "confirmado" for x in fs)
    cards = "".join(f'<div class="card" style="border-color:{COLORS[s]}"><b>{cnt[s]}</b><span>{SEV_PT[s]}</span></div>' for s in reversed(SEV))
    items = []
    for i, x in enumerate(fs, 1):
        st = '<span class="st ok">Confirmado</span>' if x["status"] == "confirmado" else '<span class="st sus">Suspeita</span>'
        items.append(f'<article><h3><span class="sev" style="background:{COLORS[x["severity"]]}">{SEV_PT[x["severity"]]}</span> {st} {i}. {e(x["title"])}</h3>'
            f'<dl><dt>Onde</dt><dd><code>{e(_where(x["target"]))}</code></dd><dt>Impacto</dt><dd>{e(x["impact"])}</dd>'
            f'<dt>O que vimos</dt><dd>{e(x["evidence"])}</dd><dt>Como corrigir</dt><dd>{e(x["recommendation"])}</dd>'
            f'<dt>Como reproduzir</dt><dd><code>{e(x["repro"] or "-")}</code></dd></dl>'
            f'<details><summary>Evidência técnica</summary><pre>{e(_proof_text(x["proof"]))}</pre></details></article>')
    return f"""<!doctype html><html lang="pt-BR"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Relatório de Auditoria de Segurança</title><style>
*{{box-sizing:border-box}}body{{font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif;margin:0;color:#1f2933;background:#f5f7fa;line-height:1.45}}
header{{background:#102a43;color:#fff;padding:20px 16px}}header h1{{margin:0 0 4px;font-size:1.35rem}}header p{{margin:2px 0;opacity:.85;font-size:.9rem}}
main{{max-width:900px;margin:auto;padding:12px}}h2{{font-size:1.1rem;margin:18px 0 8px}}
.cards{{display:grid;grid-template-columns:repeat(5,1fr);gap:8px}}.card{{background:#fff;border-top:5px solid;border-radius:8px;padding:8px;text-align:center}}
.card b{{display:block;font-size:1.5rem}}.card span{{font-size:.75rem}}
article{{background:#fff;border-radius:10px;padding:12px 14px;margin:10px 0;box-shadow:0 1px 2px #0001}}article h3{{font-size:1rem;margin:0 0 8px}}
.sev,.st{{display:inline-block;color:#fff;border-radius:4px;padding:1px 7px;font-size:.72rem;vertical-align:middle}}.st.ok{{background:#2e7d32}}.st.sus{{background:#78909c}}
dl{{margin:0}}dt{{font-weight:600;font-size:.8rem;color:#52606d;margin-top:6px}}dd{{margin:0}}code,pre{{font-size:.78rem;word-break:break-all;white-space:pre-wrap}}
pre{{background:#f0f4f8;padding:8px;border-radius:6px;overflow-x:auto}}footer{{color:#7b8794;font-size:.8rem;padding:16px}}
@media (max-width:480px){{.cards{{grid-template-columns:repeat(3,1fr)}}header h1{{font-size:1.15rem}}main{{padding:8px}}}}
</style></head><body><header><h1>Relatório de Auditoria de Segurança</h1>
<p>Cliente: {e(meta.get('client_name','Laboratório CyberSwarm'))}</p><p>Autorização: {e(meta.get('authorization_ref','LAB (ambiente próprio)'))}</p>
<p>Análise nº {rid} · {time.strftime('%d/%m/%Y %H:%M')}</p></header><main>
<h2>Resumo</h2><div class="cards">{cards}</div>
<p><b>{len(fs)}</b> pontos encontrados: <b>{conf}</b> confirmados com evidência e <b>{len(fs)-conf}</b> suspeitas para verificar. Corrija primeiro os Críticos e Altos.</p>
{''.join(f'<h2>{e(t)}</h2><article><ul>' + ''.join(f'<li>{e(x)}</li>' for x in ls) + '</ul></article>' for t, ls in (extra or []))}
<h2>Detalhes</h2>{''.join(items) or '<p>Nenhum problema encontrado.</p>'}</main>
<footer>Verificação automática e passiva feita com autorização do responsável, só no escopo autorizado. Não substitui um teste de invasão manual. Gerado por CyberSwarm.</footer></body></html>"""
def _l1(s): return str(s).replace("—", "-").replace("·", "-").replace("…", "...").replace("’", "'").replace("“", '"').replace("”", '"').encode("latin-1", "replace").decode("latin-1")
def export_pdf(rid, fs, cnt, meta, path, html_path=None, extra=None):
    try:
        from fpdf import FPDF
    except ImportError:
        return pdf_via_chrome(html_path, path) if html_path else None
    class P(FPDF):
        def footer(self):
            self.set_y(-12); self.set_font("Helvetica", "I", 8); self.set_text_color(120)
            self.cell(0, 8, _l1(f"CyberSwarm - Relatório confidencial - página {self.page_no()}/{{nb}}"), align="C")
    pdf = P(format="A4"); pdf.alias_nb_pages(); pdf.set_auto_page_break(True, 15); pdf.add_page()
    W = pdf.w - pdf.l_margin - pdf.r_margin
    def txt(s, size=10, style="", color=(31, 41, 51), h=5, font="Helvetica"):
        pdf.set_font(font, style, size); pdf.set_text_color(*color); pdf.multi_cell(W, h, _l1(s), new_x="LMARGIN", new_y="NEXT")
    pdf.set_fill_color(16, 42, 67); pdf.rect(0, 0, pdf.w, 42, "F"); pdf.set_y(12)
    txt("Relatório de Auditoria de Segurança de Site", 18, "B", (255, 255, 255), 8)
    txt(f"Cliente: {meta.get('client_name','Laboratório CyberSwarm')}   |   Análise nº {rid}   |   {time.strftime('%d/%m/%Y')}", 10, "", (220, 230, 240))
    pdf.set_y(50); txt(f"Autorização: {meta.get('authorization_ref','LAB (ambiente próprio)')}", 9, "", (90, 100, 110))
    pdf.ln(2); txt("Resumo", 14, "B"); cw = W / 5
    for s in reversed(SEV):
        r, g, b = (int(COLORS[s][i:i + 2], 16) for i in (1, 3, 5)); pdf.set_fill_color(r, g, b); pdf.set_text_color(255); pdf.set_font("Helvetica", "B", 11)
        pdf.cell(cw - 2, 12, _l1(f"{cnt[s]} {SEV_PT[s]}"), fill=True, align="C"); pdf.cell(2, 12, "")
    pdf.ln(15); conf = sum(x["status"] == "confirmado" for x in fs)
    txt(f"{len(fs)} pontos encontrados: {conf} confirmados com evidência reproduzível e {len(fs)-conf} suspeitas. Prioridade: corrigir Críticos e Altos primeiro.")
    for title, lines in extra or []:
        pdf.ln(3); txt(title, 13, "B")
        for x in lines: txt("- " + x, 9, h=4.5)
    pdf.ln(3); txt("Achados", 14, "B")
    for i, x in enumerate(fs, 1):
        if pdf.get_y() > pdf.h - 60: pdf.add_page()
        r, g, b = (int(COLORS[x["severity"]][j:j + 2], 16) for j in (1, 3, 5))
        pdf.ln(2); pdf.set_draw_color(r, g, b); pdf.set_line_width(0.8); y = pdf.get_y(); pdf.line(pdf.l_margin, y, pdf.l_margin + W, y); pdf.ln(1)
        txt(f"{i}. [{SEV_PT[x['severity']]} - {x['status'].capitalize()}] {x['title']}", 11, "B", (r, g, b))
        for lab, val in (("Onde", _where(x["target"])), ("Impacto", x["impact"]), ("O que vimos", x["evidence"]), ("Como corrigir", x["recommendation"]), ("Como reproduzir", x["repro"] or "-")):
            pdf.set_font("Helvetica", "B", 9); pdf.set_text_color(82, 96, 109); pdf.multi_cell(W, 4.5, _l1(lab + ":"), new_x="LMARGIN", new_y="NEXT")
            txt(val, 9, "", h=4.5)
        pf = _proof_text(x["proof"])
        if len(pf) > 700: pf = pf[:700] + "\n[...]"
        pdf.set_fill_color(240, 244, 248); pdf.set_font("Courier", "", 7.5); pdf.set_text_color(40)
        pdf.multi_cell(W, 3.6, _l1(pf), fill=True, new_x="LMARGIN", new_y="NEXT")
    pdf.ln(4); txt("Verificação automática e passiva realizada com autorização do responsável, apenas no escopo autorizado. Não substitui um teste de invasão manual.", 8, "I", (120, 120, 120))
    pdf.output(path); return path
def find_chrome():
    for c in ("google-chrome", "chromium", "chromium-browser", "chrome"):
        p = shutil.which(c)
        if p: return p
    return None
def _chrome(args):
    ch = find_chrome()
    if not ch: return False
    with tempfile.TemporaryDirectory() as ud:
        try: r = subprocess.run([ch, "--headless=new", "--no-sandbox", "--disable-gpu", "--hide-scrollbars", f"--user-data-dir={ud}"] + args, capture_output=True, timeout=30)
        except subprocess.TimeoutExpired: return False
    return r.returncode == 0
def pdf_via_chrome(html_path, pdf_path):
    return pdf_path if _chrome([f"--print-to-pdf={pdf_path}", "--no-pdf-header-footer", "file://" + os.path.abspath(html_path)]) and os.path.exists(pdf_path) else None
def mobile_screenshot(html_path, png_path, width=390, height=844):
    """Returns (png_path or None, page scrollWidth or None). Playwright first (measures overflow), Chrome CLI fallback."""
    try:
        from playwright.sync_api import sync_playwright
        with sync_playwright() as pw:
            kw = {"args": ["--no-sandbox"]}; ch = find_chrome()
            if ch: kw["executable_path"] = ch
            b = pw.chromium.launch(**kw)
            pg = b.new_page(viewport={"width": width, "height": height}, device_scale_factor=2, is_mobile=True)
            pg.goto("file://" + os.path.abspath(html_path)); pg.screenshot(path=png_path)
            sw = pg.evaluate("document.documentElement.scrollWidth"); b.close()
            return png_path, sw
    except Exception:
        pass
    ok = _chrome([f"--window-size={width},{height}", "--force-device-scale-factor=2", f"--screenshot={png_path}", "file://" + os.path.abspath(html_path)])
    return (png_path if ok and os.path.exists(png_path) else None), None
def compare_runs(db, old, new):
    A = {f["fingerprint"]: f for f in db.findings(old)}; B = {f["fingerprint"]: f for f in db.findings(new)}
    return {"novos": [B[k] for k in B if k not in A], "corrigidos": [A[k] for k in A if k not in B], "persistentes": [B[k] for k in B if k in A]}
