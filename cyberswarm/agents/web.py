"""Passive web auditor: GET/HEAD/OPTIONS only, in-scope only, via rate-limited Net."""
import asyncio, re, uuid
from urllib.parse import urljoin
from ..registry import Agent, register
from ..net import http_proof
HEADERS = [("content-security-policy", "web.header.csp"), ("x-frame-options", "web.header.xfo"),
           ("x-content-type-options", "web.header.xcto"), ("referrer-policy", "web.header.referrer")]
TEST_ORIGIN = "https://cyberswarm-cors-test.invalid"
def _mask_env(b):
    return "\n".join(re.sub(r"=(.*)", "=****", l) for l in b.decode("utf-8", "replace").splitlines()[:5]).encode()
@register
class WebAuditor(Agent):
    name = "web"
    async def run(self, target): return await asyncio.to_thread(self._run, target)
    def _run(self, t):
        self.scope.check_url(t); out = []; https = t.startswith("https://"); curl = f"curl -ik '{t}'"
        st, h, body = self.net.request(t)
        proof = http_proof(t, "GET", {}, st, {k: v for k, v in h.items() if k.lower() != "date"})
        hl = {k.lower(): v for k, v in h.items()}
        for hn, cid in HEADERS:
            if hn not in hl: out.append(self.finding(cid, t, f"HTTP {st} sem o cabeçalho {hn}", proof, repro=curl))
        if re.search(r"\d", hl.get("server", "")):
            out.append(self.finding("web.server_version", t, f"Server: {hl['server']}", proof, repro=curl))
        for c in h.get_all("Set-Cookie") or []:
            lc = c.lower(); nm = c.split("=")[0].strip()
            for flag, cid in (("httponly", "web.cookie.httponly"), ("secure", "web.cookie.secure"), ("samesite", "web.cookie.samesite")):
                if flag == "secure" and not https: continue
                if not re.search(rf";\s*{flag}\b", lc):
                    out.append(self.finding(cid, t, f"Set-Cookie {nm} sem {flag}", proof, nm, curl))
        if not https:
            out.append(self.finding("web.no_https", t, f"HTTP {st} servido em http:// sem redirecionar para HTTPS", proof, repro=curl))
        # CORS (GET with test Origin)
        oh = {"Origin": TEST_ORIGIN}; st2, h2, _ = self.net.request(t, headers=oh)
        acao = h2.get("Access-Control-Allow-Origin", ""); acac = (h2.get("Access-Control-Allow-Credentials") or "").lower() == "true"
        cp = http_proof(t, "GET", oh, st2, h2, keep={"access-control-allow-origin", "access-control-allow-credentials"})
        cc = f"curl -ik -H 'Origin: {TEST_ORIGIN}' '{t}'"
        if acao == TEST_ORIGIN:
            out.append(self.finding("web.cors.reflect_creds" if acac else "web.cors.reflect", t, f"Origin {TEST_ORIGIN} refletido; credentials={acac}", cp, repro=cc))
        elif acao == "*":
            out.append(self.finding("web.cors.wildcard", t, "Access-Control-Allow-Origin: *", cp, repro=cc))
        # Methods (OPTIONS only - never sends PUT/DELETE/TRACE)
        st3, h3, _ = self.net.request(t, method="OPTIONS")
        allow = {m.strip().upper() for m in (h3.get("Allow") or h3.get("Access-Control-Allow-Methods") or "").split(",") if m.strip()}
        mp = http_proof(t, "OPTIONS", {}, st3, h3, keep={"allow", "access-control-allow-methods"}); mc = f"curl -ik -X OPTIONS '{t}'"
        if "TRACE" in allow: out.append(self.finding("web.methods.trace", t, "OPTIONS anuncia TRACE", mp, repro=mc))
        risky = sorted(allow & {"PUT", "DELETE", "PATCH"})
        if risky: out.append(self.finding("web.methods.risky", t, f"OPTIONS anuncia {', '.join(risky)}", mp, ", ".join(risky), mc))
        # Exposed files with soft-404 baseline to avoid false positives
        base_url = urljoin(t.rstrip("/") + "/", f"cyberswarm-404-{uuid.uuid4().hex[:8]}")
        _, _, baseline = self.net.request(base_url)
        checks = [("/.git/HEAD", "web.exposed.git", lambda b: b.startswith(b"ref: ")),
                  ("/.env", "web.exposed.env", lambda b: bool(re.search(rb"(?m)^[A-Z][A-Z0-9_]*=", b)) and b"<html" not in b.lower()),
                  ("/backup.zip", "web.exposed.backup", lambda b: b.startswith(b"PK\x03\x04"))]
        for path, cid, ok in checks:
            url = urljoin(t.rstrip("/") + "/", path.lstrip("/")); s, hh, b = self.net.request(url)
            if s == 200 and b != baseline and ok(b):
                shown = _mask_env(b) if cid == "web.exposed.env" else b[:60]
                out.append(self.finding(cid, url, f"HTTP 200 em {path} com conteúdo característico ({len(b)} bytes)",
                                        http_proof(url, "GET", {}, s, hh, shown, keep={"content-type", "content-length"}), repro=f"curl -ik '{url}'"))
        return out
