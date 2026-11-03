"""INTENTIONALLY VULNERABLE local lab (HTTP + HTTPS). Binds to 127.0.0.1 only. Fake data only."""
import datetime, http.server, json, os, ssl, subprocess, threading, warnings
FAKE = {"/": (200, "text/html", b"<h1>Lab CyberSwarm</h1>"),
        "/.env": (200, "text/plain", b"DB_PASSWORD=fake_lab_password\nAPI_KEY=fake123\n"),
        "/.git/HEAD": (200, "text/plain", b"ref: refs/heads/main\n"),
        "/api/users": (200, "application/json", json.dumps([{"id": 1, "name": "demo"}]).encode()),
        "/api/health": (200, "application/json", b'{"ok":true}'),
        "/api/crash": (500, "text/plain", b"Traceback (most recent call last):\n  File app.py line 1\nException: boom")}
class H(http.server.BaseHTTPRequestHandler):
    server_version = "LabServer/1.0"
    def do_GET(self):
        st, ct, body = FAKE.get(self.path, (404, "text/plain", b"not found"))
        self.send_response(st); self.send_header("Content-Type", ct); self.send_header("Content-Length", str(len(body)))
        if self.path == "/": self.send_header("Set-Cookie", "session=abc123; Path=/")
        if self.path == "/api/health": self.send_header("X-RateLimit-Limit", "100")
        if self.headers.get("Origin"):
            self.send_header("Access-Control-Allow-Origin", self.headers["Origin"]); self.send_header("Access-Control-Allow-Credentials", "true")
        self.end_headers(); self.wfile.write(body)
    def do_OPTIONS(self):
        self.send_response(200); self.send_header("Allow", "GET, POST, PUT, DELETE, TRACE, OPTIONS"); self.send_header("Content-Length", "0"); self.end_headers()
    def log_message(self, *a): pass
CERT_DIR = os.path.join(os.path.expanduser("~"), ".cache", "cyberswarm", "lab-cert")
def lab_cert(days=20):
    """Self-signed cert for CN/SAN lab.cyberswarm.invalid (so 127.0.0.1 = hostname mismatch), short validity (expiring)."""
    os.makedirs(CERT_DIR, exist_ok=True); crt, key = os.path.join(CERT_DIR, "lab.crt"), os.path.join(CERT_DIR, "lab.key")
    if os.path.exists(crt):
        try:
            from cryptography import x509
            na = x509.load_pem_x509_certificate(open(crt, "rb").read()).not_valid_after_utc
            if (na - datetime.datetime.now(datetime.timezone.utc)).days >= 5: return crt, key
        except ImportError: return crt, key
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import NameOID
        k = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "lab.cyberswarm.invalid")])
        now = datetime.datetime.now(datetime.timezone.utc)
        c = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(k.public_key()).serial_number(x509.random_serial_number())
             .not_valid_before(now - datetime.timedelta(days=1)).not_valid_after(now + datetime.timedelta(days=days))
             .add_extension(x509.SubjectAlternativeName([x509.DNSName("lab.cyberswarm.invalid")]), False).sign(k, hashes.SHA256()))
        open(key, "wb").write(k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption()))
        open(crt, "wb").write(c.public_bytes(serialization.Encoding.PEM))
    except ImportError:
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", key, "-out", crt, "-days", str(days),
                        "-subj", "/CN=lab.cyberswarm.invalid", "-addext", "subjectAltName=DNS:lab.cyberswarm.invalid"], check=True, capture_output=True)
    os.chmod(key, 0o600)
    return crt, key
class Srv(http.server.ThreadingHTTPServer):
    daemon_threads = True
    def handle_error(self, request, client_address): pass  # TLS probes close connections abruptly
def start(port=8088):
    srv = Srv(("127.0.0.1", port), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start(); return srv
def start_https(port=8443):
    crt, key = lab_cert()
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); ctx.load_cert_chain(crt, key)
    try: ctx.set_ciphers("DEFAULT:@SECLEVEL=0")
    except ssl.SSLError: pass
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning); ctx.minimum_version = ssl.TLSVersion.TLSv1  # intentionally weak
    srv = Srv(("127.0.0.1", port), H)
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    threading.Thread(target=srv.serve_forever, daemon=True).start(); return srv
