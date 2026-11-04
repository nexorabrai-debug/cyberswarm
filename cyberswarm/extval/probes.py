"""Generic passive probes (GET/HEAD only via the core rate-limited Net). Written as generic checks, not lab-specific paths,
EXCEPT well-known conventional paths (robots.txt, /metrics, common OpenAPI/GraphQL locations)."""
import asyncio, json, re, uuid
from urllib.parse import urljoin, urlencode
from ..registry import Agent, register
from ..net import http_proof
API_DOCS = ["/openapi.json", "/swagger.json", "/api-docs/swagger.json", "/v3/api-docs", "/api/swagger.json"]
GQL_PATHS = ["/graphql", "/api/graphql", "/v1/graphql"]
SENSITIVE_KEYS = re.compile(r'"(password|passwd|password_hash|pwd|secret|api_key|apikey|private_key|totpsecret)"\s*:\s*"[^"]{3,}"', re.I)
TRACE = re.compile(rb"Traceback \(most recent call last\)|\n\s+at [\w$.<>]+ \(|java\.lang\.\w+Exception|at [\w.]+\([\w]+\.java:\d+\)|id=[\"\']stacktrace[\"\']|>\s*at\s+/[\w./-]+|<li>[^<]*\bat\b")
def _u(base, path): return urljoin(base.rstrip("/") + "/", path.lstrip("/"))
class _Base(Agent):
    async def run(self, target): return await asyncio.to_thread(self._run, target)
    def baseline(self, t):
        _, _, b = self.net.request(_u(t, f"cyberswarm-404-{uuid.uuid4().hex[:8]}")); return b
    def hit(self, cid, url, ev, st, h, body, detail="", headers=None):
        return self.finding(cid, url, ev, http_proof(url, "GET", headers or {}, st, h, body[:300], keep={"content-type"}), detail, f"curl -i '{url}'")
@register
class Discovery(_Base):
    """robots.txt → Disallow paths → directory listing; /metrics; OpenAPI docs; error page with stack trace."""
    name = "discovery"
    def _run(self, t):
        self.scope.check_url(t); out = []; base = self.baseline(t)
        st, h, rb = self.net.request(_u(t, "/robots.txt"))
        paths = re.findall(rb"(?im)^\s*Disallow:\s*(/\S*)", rb) if st == 200 else []
        for p in [x.decode() for x in paths][:20]:
            if "*" in p or p == "/": continue
            url = _u(t, p); s, hh, b = self.net.request(url, read=8192)
            if s == 200 and b != base and re.search(rb"(?i)<title>\s*(index of|listing directory)|directory listing for", b):
                out.append(self.hit("web.dirlisting", url, f"HTTP 200 em {p} (listado em robots.txt) com página de listagem", s, hh, b, p))
        url = _u(t, "/metrics"); s, hh, b = self.net.request(url)
        if s == 200 and re.search(rb"(?m)^# (HELP|TYPE) \w+", b):
            out.append(self.hit("web.metrics_exposed", url, "HTTP 200 em /metrics com formato Prometheus (# HELP/# TYPE)", s, hh, b))
        for p in API_DOCS:
            url = _u(t, p); s, hh, b = self.net.request(url)
            if s == 200 and re.search(rb'"(openapi|swagger)"\s*:', b):
                out.append(self.hit("web.api_docs_exposed", url, f"HTTP 200 em {p} com documento OpenAPI/Swagger", s, hh, b, p)); break
        for p in (f"/api/cyberswarm-{uuid.uuid4().hex[:6]}", f"/rest/cyberswarm-{uuid.uuid4().hex[:6]}"):
            url = _u(t, p); s, hh, b = self.net.request(url, read=16384)
            if s >= 400 and TRACE.search(b):
                out.append(self.hit("web.error_stacktrace", url, f"HTTP {s} com stack trace no corpo", s, hh, b, p)); break
        # logs e docs convencionais (GET) — só confirma conteúdo característico
        for p in ("/support/logs/", "/logs/", "/log/"):
            url = _u(t, p); s, hh, b = self.net.request(url, read=8192)
            if s != 200: continue
            text = b.decode("utf-8", "replace")
            name = None
            for part in text.replace("'", '"').split('href="')[1:]:
                href = part.split('"', 1)[0]
                if "access.log" in href or href.endswith(".log"):
                    name = href; break
            if not name: continue
            lurl = _u(url, name); ls, lh, lb = self.net.request(lurl, read=4096)
            if ls == 200 and (b"HTTP/" in lb or re.search(rb"\d+\.\d+\.\d+\.\d+", lb)):
                out.append(self.hit("web.access_log", lurl, f"HTTP 200 em log de acesso ({p})", ls, lh, lb[:200], p)); break
        for p in ("/ftp/acquisitions.md", "/ftp/legal.md"):
            url = _u(t, p); s, hh, b = self.net.request(url, read=4096)
            if s == 200 and b != base and (b.startswith(b"#") or b"confidential" in b.lower() or len(b) > 40):
                out.append(self.hit("web.confidential_doc", url, f"HTTP 200 em documento em /ftp ({p})", s, hh, b[:200], p)); break
        return out
@register
class GraphQLProbe(_Base):
    """Read-only GraphQL queries via GET: introspection, IDE exposed, field suggestions, stack traces. No mutations, no batching/DoS."""
    name = "graphql"
    def q(self, ep, query):
        url = ep + "?" + urlencode({"query": query}); st, h, b = self.net.request(url, read=16384); return url, st, h, b
    def _run(self, t):
        self.scope.check_url(t); out = []
        for p in GQL_PATHS:
            ep = _u(t, p); url, st, h, b = self.q(ep, "{__typename}")
            if b'"data"' not in b and b'"errors"' not in b: continue
            url, st, h, b = self.q(ep, "{__schema{queryType{name} types{name}}}")
            if st == 200 and b'"__schema"' in b and b'"types"' in b:
                out.append(self.hit("gql.introspection", url, f"Consulta __schema respondida (HTTP {st})", st, h, b, p))
            url, st, h, b = self.q(ep, "{cyberswarmx}")
            if re.search(rb"Did you mean", b):
                out.append(self.hit("gql.suggestions", url, "Erro sugere nomes de campos ('Did you mean')", st, h, b, p))
            if TRACE.search(b) or b'"traceback"' in b.lower() or b'"stack"' in b:
                out.append(self.hit("gql.stacktrace", url, "Erro GraphQL com stack trace", st, h, b, p))
            for ide in ("/graphiql", p):
                iurl = _u(t, ide); s, hh, ib = self.net.request(iurl, headers={"Accept": "text/html"}, read=16384)
                if s == 200 and re.search(rb"(?i)graphiql|graphql-playground|altair", ib):
                    out.append(self.hit("gql.graphiql", iurl, f"HTTP 200 em {ide} com interface GraphiQL/IDE", s, hh, ib, ide, {"Accept": "text/html"})); break
            break
        return out
@register
class ApiData(_Base):
    """Fetch an OpenAPI doc from conventional paths, GET each parameter-less GET path, flag sensitive fields in JSON."""
    name = "apidata"
    def _run(self, t):
        self.scope.check_url(t); out = []; spec = None
        for p in API_DOCS:
            s, _, b = self.net.request(_u(t, p), read=262144)
            if s == 200:
                try: spec = json.loads(b); break
                except Exception: pass
        if not spec: return out
        prefix = ((spec.get("servers") or [{}])[0].get("url") or spec.get("basePath") or "")
        if prefix.startswith("http"): prefix = ""
        for path, ops in list((spec.get("paths") or {}).items())[:60]:
            if "get" not in ops or "{" in path: continue
            url = _u(t, (prefix.rstrip("/") + path) if prefix else path); s, hh, b = self.net.request(url, read=65536)
            if s == 200:
                m = SENSITIVE_KEYS.search(b.decode("utf-8", "replace"))
                if m:
                    masked = SENSITIVE_KEYS.sub(lambda x: f'"{x.group(1)}": "****"', b.decode("utf-8", "replace"))[:300].encode()
                    out.append(self.hit("api.excessive_data", url, f"HTTP 200 em GET {path} contém campo '{m.group(1)}' com valor", s, hh, masked, f"GET {path}"))
        return out
