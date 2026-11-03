import os, shutil
from conftest import LABDATA, T
from cyberswarm.scope import Scope
def test_web(run_agent, lab_url):
    fs = run_agent("web", lab_url); ids = T(fs)
    for c in ("web.header.csp", "web.header.xfo", "web.header.xcto", "web.header.referrer", "web.server_version", "web.cookie.httponly",
              "web.cookie.samesite", "web.no_https", "web.cors.reflect_creds", "web.methods.trace", "web.methods.risky", "web.exposed.env", "web.exposed.git"):
        assert c in ids, c
    assert "web.cookie.secure" not in ids and "web.exposed.backup" not in ids
    env = next(f for f in fs if f["check_id"] == "web.exposed.env")
    assert env["proof"]["type"] == "http" and "DB_PASSWORD=****" in env["proof"]["response"] and "fake_lab_password" not in str(env)
def test_web_clean_and_soft404_no_false_positives(run_agent, ctx):
    import http.server, threading
    class H(http.server.BaseHTTPRequestHandler):  # hardened
        server_version, sys_version = "Hardened", ""  # answers 200 HTML for every path (soft-404)
        def do_GET(self):
            self.send_response(200)
            for k, v in {"Content-Security-Policy": "default-src 'self'", "X-Frame-Options": "DENY", "X-Content-Type-Options": "nosniff", "Referrer-Policy": "no-referrer"}.items(): self.send_header(k, v)
            self.send_header("Set-Cookie", "s=1; HttpOnly; SameSite=Lax"); self.end_headers(); self.wfile.write(b"<html>A=1 ref: x</html>")
        def do_OPTIONS(self): self.send_response(200); self.send_header("Allow", "GET, HEAD, OPTIONS"); self.end_headers()
        def log_message(self, *a): pass
    s = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H); threading.Thread(target=s.serve_forever, daemon=True).start()
    try: ids = T(run_agent("web", f"http://127.0.0.1:{s.server_address[1]}"))
    finally: s.shutdown()
    assert ids == ["web.no_https"]  # only true issue
def test_tls(run_agent, lab_https):
    fs = run_agent("tls", lab_https); ids = T(fs)
    for c in ("tls.self_signed", "tls.hostname_mismatch", "tls.expiring", "tls.hsts", "tls.old_protocol"): assert c in ids, c
    assert sorted(f["title"].split(": ")[-1] for f in fs if f["check_id"] == "tls.old_protocol") == ["TLS 1.0", "TLS 1.1"]
    assert "tls.expired" not in ids and all(f["proof"] for f in fs)
def test_tls_skips_http(run_agent, lab_url): assert run_agent("tls", lab_url) == []
def test_tls_hostname_and_expiry_logic(tmp_path):
    import datetime
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID
    from cyberswarm.agents.tls import name_matches
    k = ec.generate_private_key(ec.SECP256R1()); n = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "x")]); now = datetime.datetime.now(datetime.timezone.utc)
    c = (x509.CertificateBuilder().subject_name(n).issuer_name(n).public_key(k.public_key()).serial_number(1).not_valid_before(now).not_valid_after(now)
         .add_extension(x509.SubjectAlternativeName([x509.DNSName("*.acme.test"), x509.IPAddress(__import__("ipaddress").ip_address("127.0.0.1"))]), False).sign(k, hashes.SHA256()))
    assert name_matches("www.acme.test", c)[0] and not name_matches("a.b.acme.test", c)[0] and name_matches("127.0.0.1", c)[0] and not name_matches("evil.test", c)[0]
def test_api(run_agent, ctx, lab_url):
    ctx.options["api_base"] = lab_url; fs = run_agent("api", os.path.join(LABDATA, "openapi.json")); t = [f["title"] for f in fs]
    assert any("DELETE /api/users" in x and "sem autenticação" in x for x in t) and "api.unauth.public" in T(fs)
    assert "api.verbose_error.doc" in T(fs) and "api.verbose_error.live" in T(fs)
    assert not any("/api/admin" in x and "autenticação" in x for x in t)
    assert not any(f["check_id"] == "api.ratelimit.live" and "/api/health" in f["target"] for f in fs)  # lab sends X-RateLimit on health
    assert all(f["proof"].get("line", 1) > 0 for f in fs)
def test_cloud(run_agent):
    fs = run_agent("cloud", os.path.join(LABDATA, "terraform")); ids = T(fs)
    assert ids.count("secret.assignment") == 2 and "secret.aws_key" in ids and "cloud.s3_public_acl" in ids and "cloud.s3_block_disabled" in ids
    sg = {f["check_id"]: f["title"] for f in fs if f["check_id"].startswith("cloud.sg")}
    assert "porta 22" in sg["cloud.sg_admin_open"] and "porta 443" in sg["cloud.sg_open"]
    assert all(f["proof"]["type"] == "file" and f["proof"]["line"] > 0 for f in fs)
def test_code(run_agent):
    ids = sorted(T(run_agent("code", os.path.join(LABDATA, "src"))))
    assert ids == sorted(["secret.github_token", "secret.slack_token", "secret.google_api_key", "secret.jwt", "secret.high_entropy", "secret.private_key"])
def test_mobile(run_agent):
    fs = run_agent("mobile", os.path.join(LABDATA, "android")); t = " ".join(f["title"] for f in fs)
    assert {"android.debuggable", "android.allow_backup", "android.cleartext", "android.exported"} <= set(T(fs))
    assert ".AdminActivity" in t and ".SyncService" in t and ".DataProvider" in t and ".MainActivity" not in t and ".SafeReceiver" not in t
    assert next(f for f in fs if f["check_id"] == "android.allow_backup")["proof"] == {}  # implicit -> no proof
def test_ios(run_agent):
    assert sorted(T(run_agent("ios", os.path.join(LABDATA, "ios")))) == sorted(["ios.ats_disabled", "ios.insecure_domain", "ios.old_tls_domain", "ios.file_sharing", "ios.url_scheme"])
def test_static_agents_respect_scope(run_agent, tmp_path):
    import pytest
    from cyberswarm.scope import OutOfScope
    for a in ("api", "cloud", "mobile", "ios", "code"):
        with pytest.raises(OutOfScope): run_agent(a, str(tmp_path))
