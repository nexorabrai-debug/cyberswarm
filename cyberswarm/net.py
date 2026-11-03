"""All network I/O goes through here: scope check, rate limit, timeout, request budget, audit."""
import ssl, threading, time, urllib.request, urllib.error
from urllib.parse import urlparse
class BudgetExceeded(Exception): pass
class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k): return None  # never follow redirects off-scope
class Net:
    def __init__(self, scope, audit, rate_per_sec=5.0, timeout=5.0, max_requests=300):
        self.scope, self.audit, self.timeout, self.max = scope, audit, timeout, max_requests
        self.interval = 1.0 / rate_per_sec; self.count = 0; self.last = {}; self.lock = threading.Lock()
        ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE  # TLS issues reported by tls agent
        self.opener = urllib.request.build_opener(_NoRedirect, urllib.request.HTTPSHandler(context=ctx))
    def _throttle(self, host):
        with self.lock:
            self.count += 1
            if self.count > self.max: raise BudgetExceeded(f"limite de {self.max} requisições atingido")
            wait = self.last.get(host, 0) + self.interval - time.monotonic()
            if wait > 0: time.sleep(wait)
            self.last[host] = time.monotonic()
    def request(self, url, method="GET", headers=None, read=4096, data=None):
        """GET/HEAD/OPTIONS em qualquer alvo no escopo. POST/PUT só em 127.0.0.1/localhost (lab) — ver agents/labauth.py."""
        self.scope.check_url(url)
        host = (urlparse(url).hostname or "").lower()
        if method in ("GET", "HEAD", "OPTIONS"):
            if data: raise PermissionError("GET/HEAD/OPTIONS sem corpo")
        elif method in ("POST", "PUT"):
            if host not in ("127.0.0.1", "localhost"): raise PermissionError("método ativo só em laboratório 127.0.0.1")
        else: raise PermissionError("método HTTP não permitido")
        self._throttle(host)
        req = urllib.request.Request(url, data=data, method=method, headers={"User-Agent": "CyberSwarm-defensive/1.0", **(headers or {})})
        try:
            with self.opener.open(req, timeout=self.timeout) as r: st, h, b = r.status, r.headers, r.read(read)
        except urllib.error.HTTPError as e: st, h, b = e.code, e.headers, e.read(read)
        self.audit.log("http", method=method, url=url, status=st, lab_active=method in ("POST", "PUT"))
        return st, h, b
def http_proof(url, method, req_headers, status, resp_headers, body=b"", keep=None):
    u = urlparse(url)
    req = f"{method} {u.path or '/'} HTTP/1.1\nHost: {u.netloc}" + "".join(f"\n{k}: {v}" for k, v in (req_headers or {}).items())
    hs = [(k, v) for k, v in resp_headers.items() if keep is None or k.lower() in keep]
    resp = f"HTTP/1.1 {status}" + "".join(f"\n{k}: {v}" for k, v in hs)
    if body: resp += "\n\n" + body[:160].decode("utf-8", "replace")
    return {"type": "http", "request": req, "response": resp,
            "curl": f"curl -i -X {method} " + "".join(f"-H '{k}: {v}' " for k, v in (req_headers or {}).items()) + f"'{url}'"}
