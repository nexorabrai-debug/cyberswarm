"""External educational labs (third-party, intentionally vulnerable). ALL bound to 127.0.0.1 by scripts/start_labs.sh."""
import os, socket
LABS_DIR = os.environ.get("CYBERSWARM_LABS", os.path.expanduser("~/labs"))
LABS = {
    "juice-shop": {"kind": "web", "url": "http://127.0.0.1:3000", "port": 3000, "project": "OWASP Juice Shop v20.3.0"},
    "webgoat": {"kind": "web", "url": "http://127.0.0.1:8080/WebGoat", "port": 8080, "project": "OWASP WebGoat v2026.4"},
    "vampi": {"kind": "web", "url": "http://127.0.0.1:5002", "port": 5002, "project": "VAmPI (erev0s)"},
    "dvga": {"kind": "web", "url": "http://127.0.0.1:5013", "port": 5013, "project": "DVGA (dolevf)"},
    "insecurebankv2": {"kind": "apk", "apk": os.path.join(LABS_DIR, "InsecureBankv2.apk"), "project": "Android-InsecureBankv2 (dineshshetty)"},
    "crapi": {"kind": "skip", "project": "OWASP crAPI", "reason": "exige Docker/Docker Compose (7+ serviços: Java, Go, Python, Postgres, MongoDB); Docker/Podman indisponíveis nesta máquina e sem permissão de instalar pacotes via apt (proxy retorna 500)."},
}
def port_open(port, host="127.0.0.1", timeout=0.5):
    try:
        with socket.create_connection((host, port), timeout=timeout): return True
    except OSError: return False
def status(name):
    l = LABS[name]
    if l["kind"] == "web": return "up" if port_open(l["port"]) else "down"
    if l["kind"] == "apk": return "up" if os.path.exists(l["apk"]) else "down"
    return "nao_executavel"
