"""Pontuação de confiança (0–100) e detecção de contradições. Regras explícitas, sem ML — explicáveis no relatório.
Base pela prova: http/tls/tcp reproduzível 60, arquivo re-verificado 55, sem prova 15.
+20 se reproduzido (status confirmado), +10 por fonte independente adicional (máx +20), -25 se só ferramenta externa sem reprodução,
-30 se houver contradição. Faixas: alta >=75, média 45–74, baixa <45."""
from collections import defaultdict
BASE = {"http": 60, "tls": 60, "tcp": 60, "file": 55}
def _key(f): return (f.get("check_id"), f.get("target"))
def sources(f):
    s = {f.get("agent")}; s.update(f.get("corroborated_by", []) or []); return {x for x in s if x}
def contradictions(findings):
    """Contradições detectadas:
    1) mesmo (check, alvo) confirmado por uma fonte e refutado (status 'refutado'/'não reproduzido') por outra;
    2) mesmo pacote com versões diferentes em achados SCA do mesmo lockfile;
    3) severidade divergente para o mesmo (check, alvo) entre fontes."""
    by = defaultdict(list); out = []
    for f in findings: by[_key(f)].append(f)
    for k, fs in by.items():
        st = {f.get("status") for f in fs}
        if "confirmado" in st and st & {"refutado", "nao_reproduzido", "não reproduzido"}:
            out.append({"type": "status", "key": list(k), "detail": sorted(map(str, st))})
        sev = {f.get("severity") for f in fs}
        if len(sev) > 1: out.append({"type": "severidade", "key": list(k), "detail": sorted(map(str, sev))})
    vers = defaultdict(set)
    for f in findings:
        if f.get("check_id") == "sca.vulnerable_dependency" and "@" in f.get("title", ""):
            name, ver = f["title"].split(": ", 1)[-1].rsplit("@", 1); vers[(f["target"], name)].add(ver)
    # várias versões do mesmo pacote num lockfile é normal (npm aninha); só sinaliza, não penaliza
    out += [{"type": "versoes_multiplas", "key": [t, n], "detail": sorted(v), "penaliza": False} for (t, n), v in vers.items() if len(v) > 1]
    return out
def score(findings):
    con = {tuple(c["key"]) for c in contradictions(findings) if c.get("penaliza", True)}
    for f in findings:
        p = f.get("proof") or {}; s = BASE.get(p.get("type"), 15)
        if f.get("status") == "confirmado": s += 20
        s += min(20, 10 * (len(sources(f)) - 1))
        if f.get("tool") and f.get("status") != "confirmado": s -= 25
        if _key(f) in con: s -= 30
        f["confidence"] = max(0, min(100, s)); f["confidence_band"] = "alta" if s >= 75 else "média" if s >= 45 else "baixa"
    return findings
