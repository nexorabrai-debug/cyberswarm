"""TLS para o Control: certificado autoassinado por padrão (gratuito). Let's Encrypt / Cloudflare: ver docs/IMPLANTACAO.md.
Só usa cryptography (já dependência); sem invocação de processos externos."""
import datetime, ipaddress, os, ssl
def ensure_self_signed(dir_, host="127.0.0.1", days=825):
    os.makedirs(dir_, exist_ok=True)
    cert, key = os.path.join(dir_, "cert.pem"), os.path.join(dir_, "key.pem")
    if os.path.exists(cert) and os.path.exists(key): return cert, key
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID
    k = rsa.generate_private_key(65537, 2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, host)])
    san = [x509.DNSName("localhost"), x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]
    try: san.append(x509.IPAddress(ipaddress.ip_address(host)))
    except ValueError: san.append(x509.DNSName(host))
    now = datetime.datetime.now(datetime.timezone.utc)
    c = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(k.public_key())
         .serial_number(x509.random_serial_number()).not_valid_before(now).not_valid_after(now + datetime.timedelta(days=days))
         .add_extension(x509.SubjectAlternativeName(san), False).sign(k, hashes.SHA256()))
    open(key, "wb").write(k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption()))
    open(cert, "wb").write(c.public_bytes(serialization.Encoding.PEM))
    os.chmod(key, 0o600); os.chmod(cert, 0o644)
    return cert, key
def ssl_context(cert, key):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(cert, key); return ctx
