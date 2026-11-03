"""Wrappers for external OSS tools with scope lock + rate limits. RULE: a tool hit is 'suspeita' until OUR code reproduces
evidence (nuclei: re-request with core Net; MobSF: corroborated by our APK analyzer, see corroborate_mobsf)."""
import asyncio, json, os, re, signal, subprocess, sys, tempfile, time, urllib.request, uuid
from urllib.parse import urlparse, urljoin
from ..registry import Agent, register
from ..net import http_proof
from ..orchestrator import PartialResult
from ..tools import which
from .apk import mobsf_category
LOCAL = {"127.0.0.1", "localhost"}
SEVS = ("info", "low", "medium", "high", "critical")
TEMPLATES = os.environ.get("CYBERSWARM_NUCLEI_TEMPLATES", os.path.expanduser("~/labs/nuclei-templates"))
SAFE_TAGS = "exposure,misconfig,graphql,swagger,config,debug,api,logs,disclosure"
BLOCKED_TAGS = "intrusive,dos,fuzz,bruteforce,rce,sqli,xss,lfi,ssrf,injection,default-login,auth-bypass,cve,oast,file-upload,takeover,brute-force"
def scope_lock(scope, url):
    """Lab: only 127.0.0.1/localhost. Non-lab hosts only if the core scope (client authorization) allows them."""
    scope.check_url(url); host = urlparse(url).hostname
    if host not in LOCAL and not scope.client: raise PermissionError(f"ferramenta externa travada: {host} não é lab nem cliente autorizado")
    return host
def _same_origin(a, b):
    ua, ub = urlparse(a), urlparse(b)
    return (ua.hostname, ua.port or 80) == (ub.hostname, ub.port or 80)
def nuclei_cmd(target, out_jsonl, rate=10, conc=5, timeout=3):
    return [which("nuclei"), "-u", target, "-t", os.path.join(TEMPLATES, "http"), "-tags", SAFE_TAGS, "-etags", BLOCKED_TAGS,
            "-rl", str(rate), "-c", str(conc), "-timeout", str(timeout), "-retries", "0", "-jsonl", "-silent", "-no-interactsh",
            "-disable-update-check", "-dr", "-o", out_jsonl]
def run_tool(cmd, out_file, hard_timeout, audit, name):
    """Run a tool; on timeout/kill keep whatever it already wrote. Returns (lines, complete:bool, reason)."""
    audit.log("tool_start", tool=name, cmd=" ".join(cmd[:3]) + " ...")
    p = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True, start_new_session=True)
    try:
        _, err = p.communicate(timeout=hard_timeout); rc = p.returncode
        reason = "" if rc == 0 else f"{name} saiu com código {rc}: {(err or '')[-200:]}"
    except subprocess.TimeoutExpired:
        os.killpg(p.pid, signal.SIGKILL); p.wait(); rc = -9; reason = f"{name} excedeu {hard_timeout}s e foi encerrado"
    lines = open(out_file).read().splitlines() if os.path.exists(out_file) else []
    audit.log("tool_done", tool=name, rc=rc, lines=len(lines), reason=reason[:200])
    return lines, rc == 0, reason
@register
class NucleiAgent(Agent):
    """nuclei with curated non-intrusive tags; hits outside the exact authorized host:port are DISCARDED; each hit re-verified."""
    name = "nuclei"
    async def run(self, target): return await asyncio.to_thread(self._run, target)
    def reproduce(self, hit):
        url = hit.get("matched-at") or ""; tid = hit.get("template-id", "")
        if not url.startswith("http"): return None
        try: st, h, b = self.net.request(url, read=16384)
        except Exception: return None
        hl = {k.lower() for k in h.keys()}
        if tid == "http-missing-security-headers":
            mh = (hit.get("matcher-name") or "").lower()
            return http_proof(url, "GET", {}, st, h) if mh and mh not in hl else None
        if st != 200: return None
        _, _, base = self.net.request(urljoin(url, f"/cyberswarm-404-{uuid.uuid4().hex[:6]}"))
        if b == base: return None
        ex = [e for e in (hit.get("extracted-results") or []) if isinstance(e, str)]
        if ex and not any(e.encode()[:60] in b for e in ex): return None
        return http_proof(url, "GET", {}, st, h, b[:200], keep={"content-type"})
    def _run(self, target):
        scope_lock(self.scope, target)
        if not which("nuclei"): raise RuntimeError("nuclei não instalado")
        tmp = tempfile.mkdtemp(prefix="cs-nuclei-"); oj = os.path.join(tmp, "out.jsonl")
        lines, complete, reason = run_tool(self.ctx.options.get("nuclei_cmd", nuclei_cmd)(target, oj), oj,
                                           self.ctx.options.get("nuclei_timeout", 900), self.audit, "nuclei")
        out, discarded = [], 0
        for l in lines:
            try: hit = json.loads(l)
            except Exception: continue
            m = hit.get("matched-at") or hit.get("host") or ""
            if not _same_origin(m if "://" in m else "http://" + m, target):
                discarded += 1; self.audit.log("tool_hit_discarded", tool="nuclei", reason="fora do host:porta autorizado", url=m); continue
            sev = (hit.get("info") or {}).get("severity", "info"); sev = sev if sev in SEVS else "info"
            detail = hit.get("template-id", "?") + (f"[{hit['matcher-name']}]" if hit.get("matcher-name") else "")
            proof = self.reproduce(hit) or {}
            f = self.finding(f"ext.nuclei.{sev}", m, f"nuclei {detail} em {m}" + ("" if proof else " (não reproduzido pelo validador)"),
                             proof, detail, f"curl -i '{m}'")
            f["tool"] = "nuclei"; f["template"] = hit.get("template-id"); f["matcher"] = hit.get("matcher-name"); out.append(f)
        self.ctx.options.setdefault("tool_stats", {})[f"nuclei:{target}"] = {"hits": len(lines), "discarded_out_of_port": discarded, "complete": complete}
        if not complete: raise PartialResult(out, reason)
        return out
def mobsf_base(): return os.environ.get("MOBSF_URL", "http://127.0.0.1:8000")
def mobsf_key():
    k = os.environ.get("MOBSF_API_KEY")
    if not k and os.path.exists(os.path.expanduser("~/labs/mobsf.key")): k = open(os.path.expanduser("~/labs/mobsf.key")).read().strip()
    return k
def _mobsf_post(path, data, key, files=None, timeout=600):
    base = mobsf_base()
    if urlparse(base).hostname not in LOCAL: raise PermissionError("MobSF travado em 127.0.0.1")
    if files:
        bnd = uuid.uuid4().hex; name, content = files
        body = (f"--{bnd}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"{name}\"\r\nContent-Type: application/octet-stream\r\n\r\n").encode() + content + f"\r\n--{bnd}--\r\n".encode()
        ct = f"multipart/form-data; boundary={bnd}"
    else:
        body = "&".join(f"{k}={v}" for k, v in data.items()).encode(); ct = "application/x-www-form-urlencoded"
    req = urllib.request.Request(base + path, data=body, headers={"Authorization": key, "Content-Type": ct}, method="POST")
    with urllib.request.urlopen(req, timeout=timeout) as r: return json.loads(r.read())
@register
class MobSFAgent(Agent):
    """Static scan through a LOCAL MobSF (127.0.0.1). Every hit is 'suspeita' (no proof) until corroborated by our APK analyzer."""
    name = "mobsf"; kind = "path"
    async def run(self, target): return await asyncio.to_thread(self._run, target)
    def _run(self, apk):
        self.scope.check_path(apk); key = mobsf_key()
        if not key: raise RuntimeError("MobSF sem chave de API (MOBSF_API_KEY)")
        self.audit.log("tool_start", tool="mobsf", apk=os.path.basename(apk))
        up = _mobsf_post("/api/v1/upload", {}, key, files=(os.path.basename(apk), open(apk, "rb").read()))
        rep = _mobsf_post("/api/v1/scan", {"hash": up["hash"]}, key)
        self.ctx.options.setdefault("tool_stats", {})["mobsf"] = {"code_analysis": len((rep.get("code_analysis") or {}).get("findings") or {}),
                                                                  "manifest": len((rep.get("manifest_analysis") or {}).get("manifest_findings") or [])}
        out = []; sevmap = {"high": "high", "warning": "medium", "info": "info", "secure": "info"}
        for f in (rep.get("manifest_analysis") or {}).get("manifest_findings") or []:
            sev = sevmap.get(f.get("severity"), "info"); title = re.sub(r"<[^>]+>", "", f.get("title", ""))[:140]
            x = self.finding(f"ext.mobsf.{sev}", apk, f"MobSF {f.get('rule')}: {title}", {}, f"{f.get('rule')}: {title}")
            x.update(tool="mobsf", rule=f.get("rule"), category=mobsf_category(f.get("rule"), title)); out.append(x)
        for rid, f in ((rep.get("code_analysis") or {}).get("findings") or {}).items():
            sev = sevmap.get((f.get("metadata") or {}).get("severity"), "info")
            x = self.finding(f"ext.mobsf.{sev}", apk, f"MobSF código {rid}", {}, rid); x.update(tool="mobsf", rule=rid, category=mobsf_category(rid, "")); out.append(x)
        self.audit.log("tool_done", tool="mobsf", hits=len(out)); return out
def corroborate(findings):
    """MobSF hit -> 'confirmado' only if OUR apk analyzer has a confirmed finding of the same category (proof copied, source noted)."""
    ours = {}
    for f in findings:
        if f["agent"] == "apk" and f.get("status") == "confirmado": ours.setdefault(f["check_id"], f)
    n = 0
    for f in findings:
        if f.get("tool") == "mobsf":
            o = ours.get(f.get("category"))
            if o: f["proof"] = o["proof"]; f["status"] = "confirmado"; f["corroborated_by"] = o["fingerprint"]; n += 1
            else: f["status"] = "suspeita"
    return n
