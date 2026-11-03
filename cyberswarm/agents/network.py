"""Network Security module: TCP connect check (no SYN scan, no payloads). HARD-LOCKED to 127.0.0.1/localhost.
Target: tcp://127.0.0.1 ; ports from ctx.options['ports'] (default DEFAULT_PORTS). Uses nmap -sT if the selector chose it and it is installed."""
import asyncio, socket, ssl, subprocess, time
from urllib.parse import urlparse
from ..registry import Agent, register
from ..tools import which
LAB_ONLY = {"127.0.0.1", "localhost"}
DEFAULT_PORTS = [21, 22, 23, 25, 80, 443, 3306, 5432, 6379, 8080, 8088, 8443, 9200, 11211, 27017]
DATASTORE = {3306, 5432, 6379, 9200, 11211, 27017, 1433}
CLEARTEXT = {21, 23, 25, 80, 8080, 8000, 8088}
def is_tls(host, port, timeout=1.0):
    c = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT); c.check_hostname = False; c.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((host, port), timeout=timeout) as s, c.wrap_socket(s, server_hostname=host): return True
    except Exception: return False
def is_http(host, port, timeout=1.0):
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.sendall(b"HEAD / HTTP/1.0\r\nHost: 127.0.0.1\r\n\r\n"); return s.recv(5).startswith(b"HTTP/")
    except Exception: return False
def connect_scan(host, ports, timeout=0.5, interval=0.01):
    openp = []
    for p in ports:
        try:
            with socket.create_connection((host, p), timeout=timeout): openp.append(p)
        except OSError: pass
        time.sleep(interval)  # gentle rate
    return openp
def nmap_scan(host, ports):
    r = subprocess.run([which("nmap"), "-sT", "-Pn", "-n", "-p", ",".join(map(str, ports)), "-oG", "-", host], capture_output=True, text=True, timeout=120)
    return [int(x.split("/")[0]) for line in r.stdout.splitlines() if "Ports:" in line for x in line.split("Ports:")[1].split(",") if "/open/" in x]
@register
class NetworkAuditor(Agent):
    name = "network"
    async def run(self, target): return await asyncio.to_thread(self._run, target)
    def _run(self, target):
        host = urlparse(target).hostname
        if host not in LAB_ONLY: raise PermissionError(f"network: travado em 127.0.0.1 (recebido {host})")
        ports = self.ctx.options.get("ports") or DEFAULT_PORTS
        tool = (self.ctx.options.get("tools") or {}).get("network", "builtin")
        if tool == "nmap" and which("nmap"): openp = nmap_scan(host, ports)
        else: tool = "builtin"; openp = connect_scan(host, ports)
        self.ctx.options.setdefault("tool_used", {})[self.name] = tool
        self.audit.log("tcp_connect", agent=self.name, host=host, ports=len(ports), open=openp, tool=tool); out = []
        for p in openp:
            if p in DATASTORE: cid, kind = "net.open.datastore", "banco/cache"
            elif is_tls(host, p): cid, kind = "net.open.tls", "TLS"
            elif p in CLEARTEXT or is_http(host, p): cid, kind = "net.open.cleartext", "texto claro"
            else: cid, kind = "net.open.other", "desconhecido"
            cmd = f"nc -zv {host} {p}"
            proof = {"type": "tcp", "command": cmd, "observed": f"connect({host}:{p}) aceito; serviço: {kind}"}
            out.append(self.finding(cid, f"tcp://{host}:{p}", f"porta {p}/tcp aberta ({kind})", proof, f"{p}/tcp", cmd))
        return out
