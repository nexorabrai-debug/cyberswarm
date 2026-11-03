"""API auditor: static OpenAPI analysis + passive GET probe of in-scope base URL."""
import asyncio, json
from ..registry import Agent, register
from ..net import http_proof
from .common import file_proof, file_repro, find_line
SENSITIVE = ("admin", "user", "account", "payment", "token", "delete", "order")
WRITE = ("POST", "PUT", "DELETE", "PATCH")
@register
class ApiAuditor(Agent):
    name = "api"; kind = "path"
    async def run(self, target): return await asyncio.to_thread(self._run, target)
    def _run(self, p):
        self.scope.check_path(p); self.audit.log("read_file", agent=self.name, path=p)
        text = open(p).read(); lines = text.splitlines(); spec = json.loads(text); out = []
        def add(cid, ev, needle, detail="", start=0):
            n = find_line(lines, needle, start); out.append(self.finding(cid, p, ev, file_proof(p, lines, n), detail, file_repro(p, n)))
        gsec = spec.get("security")
        if not ((spec.get("components") or {}).get("securitySchemes")):
            add("api.no_security_schemes", "components.securitySchemes ausente", '"openapi"')
        for path, ops in (spec.get("paths") or {}).items():
            pl = find_line(lines, f'"{path}"')
            for method, op in ops.items():
                if not isinstance(op, dict): continue
                M = method.upper(); ml = find_line(lines, f'"{method}"', max(pl - 1, 0)); needle = f'"{method}"'
                if not op.get("security", gsec):
                    cid = "api.unauth.sensitive" if M in WRITE or any(s in path.lower() for s in SENSITIVE) else "api.unauth.public"
                    add(cid, f"{M} {path} sem 'security'", needle, f"{M} {path}", max(pl - 1, 0))
                hdrs = {h.lower() for r in (op.get("responses") or {}).values() for h in (r.get("headers") or {})}
                if not any("ratelimit" in h.replace("-", "") for h in hdrs):
                    add("api.ratelimit.doc", f"{M} {path}: nenhum X-RateLimit-* documentado", needle, f"{M} {path}", max(pl - 1, 0))
                for code, r in (op.get("responses") or {}).items():
                    if str(code).startswith("5") and any(k in json.dumps(r).lower() for k in ("stack", "trace", "exception", "debug")):
                        add("api.verbose_error.doc", f"{M} {path} {code}: {r.get('description','')}", f'"{code}"', f"{M} {path} {code}", max(ml - 1, 0))
        base = self.ctx.options.get("api_base") or (spec.get("servers") or [{}])[0].get("url", "")
        if base.startswith("http"):
            try: self.scope.check_url(base)
            except Exception as e: self.log.info(f"probe pulado (fora do escopo): {e}"); return out
            for path, ops in (spec.get("paths") or {}).items():
                if "get" not in ops or "{" in path: continue
                url = base.rstrip("/") + path; st, h, b = self.net.request(url)
                if st >= 500 and any(k in b.lower() for k in (b"traceback", b"exception", b"stack trace")):
                    out.append(self.finding("api.verbose_error.live", url, f"HTTP {st} com stack trace no corpo", http_proof(url, "GET", {}, st, h, b), f"GET {path}", f"curl -i '{url}'"))
                if st == 200 and not any(k.lower().startswith(("x-ratelimit", "ratelimit", "retry-after")) for k in h.keys()):
                    out.append(self.finding("api.ratelimit.live", url, f"HTTP {st} sem cabeçalhos de rate limit", http_proof(url, "GET", {}, st, h), f"GET {path}", f"curl -i '{url}'"))
        return out
