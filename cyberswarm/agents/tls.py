"""TLS auditor (https targets): accepted protocol versions, certificate expiry, self-signed, hostname mismatch, HSTS."""
import asyncio, datetime, ipaddress, socket, ssl, warnings
from urllib.parse import urlparse
from ..registry import Agent, register
from ..net import http_proof
try:
    from cryptography import x509
    from cryptography.x509.oid import ExtensionOID
except ImportError:  # optional dependency
    x509 = None
def _ctx(version=None):
    c = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT); c.check_hostname = False; c.verify_mode = ssl.CERT_NONE
    try: c.set_ciphers("DEFAULT:@SECLEVEL=0")
    except ssl.SSLError: pass
    if version is not None:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning); c.minimum_version = c.maximum_version = version
    return c
def handshake(host, port, version=None, timeout=5):
    with socket.create_connection((host, port), timeout=timeout) as s, _ctx(version).wrap_socket(s, server_hostname=host) as t:
        return t.version(), t.getpeercert(binary_form=True)
def name_matches(host, cert):
    try: san = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value
    except x509.ExtensionNotFound: return False, []
    dns = san.get_values_for_type(x509.DNSName); ips = [str(i) for i in san.get_values_for_type(x509.IPAddress)]
    try: ipaddress.ip_address(host); return host in ips, dns + ips
    except ValueError: pass
    for d in dns:
        if d.lower() == host.lower() or (d.startswith("*.") and host.lower().endswith(d[1:].lower()) and host.count(".") == d.count(".")): return True, dns + ips
    return False, dns + ips
@register
class TlsAuditor(Agent):
    name = "tls"
    async def run(self, target): return await asyncio.to_thread(self._run, target)
    def _run(self, t):
        self.scope.check_url(t); u = urlparse(t); out = []
        if u.scheme != "https": return out
        host, port = u.hostname, u.port or 443; hp = f"{host}:{port}"
        sc = f"openssl s_client -connect {hp} -servername {host} </dev/null 2>/dev/null | openssl x509 -noout -subject -issuer -dates -ext subjectAltName"
        self.net._throttle(host); self.audit.log("tls_handshake", host=hp, version="default")
        ver, der = handshake(host, port)
        if x509 is None:
            self.log.warning("cryptography não instalado: checagens de certificado puladas")
        else:
            cert = x509.load_der_x509_certificate(der)
            subj, iss = cert.subject.rfc4514_string(), cert.issuer.rfc4514_string()
            na = cert.not_valid_after_utc; now = datetime.datetime.now(datetime.timezone.utc)
            obs = f"subject={subj}\nissuer={iss}\nnotAfter={na:%Y-%m-%d %H:%M} UTC\nversão negociada={ver}"
            ok, names = name_matches(host, cert); obs += f"\nSAN={', '.join(names) or '(nenhum)'}"
            proof = {"type": "tls", "command": sc, "observed": obs}
            if subj == iss:
                out.append(self.finding("tls.self_signed", t, f"emissor = assunto ({subj})", proof, repro=sc))
            if not ok:
                out.append(self.finding("tls.hostname_mismatch", t, f"host {host} não está em SAN [{', '.join(names)}]", proof, repro=sc))
            if na < now:
                out.append(self.finding("tls.expired", t, f"notAfter={na:%Y-%m-%d}", proof, repro=sc))
            elif (na - now).days < 30:
                out.append(self.finding("tls.expiring", t, f"notAfter={na:%Y-%m-%d} (<30 dias)", proof, repro=sc))
        for v, label, flag in ((ssl.TLSVersion.TLSv1, "TLS 1.0", "-tls1"), (ssl.TLSVersion.TLSv1_1, "TLS 1.1", "-tls1_1")):
            self.net._throttle(host); self.audit.log("tls_handshake", host=hp, version=label)
            try: got, _ = handshake(host, port, v)
            except ssl.SSLError as e:
                if "NO_PROTOCOLS_AVAILABLE" in str(e).upper() or "no protocols available" in str(e):
                    self.log.warning(f"cliente local não suporta {label}; não testado")
                continue
            except OSError: continue
            cmd = f"openssl s_client -connect {hp} {flag} -cipher 'DEFAULT:@SECLEVEL=0' </dev/null"
            out.append(self.finding("tls.old_protocol", t, f"handshake aceito em {label}", {"type": "tls", "command": cmd, "observed": f"handshake concluído, versão negociada={got}"}, label, cmd))
        st, h, _ = self.net.request(t)
        if "strict-transport-security" not in {k.lower() for k in h.keys()}:
            out.append(self.finding("tls.hsts", t, f"HTTP {st} via HTTPS sem Strict-Transport-Security", http_proof(t, "GET", {}, st, {k: v for k, v in h.items() if k.lower() != "date"}), repro=f"curl -ik '{t}'"))
        return out
