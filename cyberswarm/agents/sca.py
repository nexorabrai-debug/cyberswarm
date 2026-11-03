"""SCA (Stage C / 2.0): dependências vulneráveis via OSV-Scanner (online, api.osv.dev) ou, offline,
Trivy/Grype (DB local baixada uma vez). Só roda se a ferramenta estiver instalada.
Prova = linha do lockfile com nome+versão + id do advisory. Sem ferramenta -> nenhum finding (não inventa)."""
import asyncio, json, os, subprocess
from ..registry import Agent, register
from ..tools import which
from .common import file_proof, file_repro
LOCKS = ("package-lock.json", "yarn.lock", "pnpm-lock.yaml", "requirements.txt", "poetry.lock", "Pipfile.lock",
         "go.sum", "Cargo.lock", "Gemfile.lock", "composer.lock", "pom.xml")
SKIP = {"node_modules", ".git", "build", "dist"}
def find_locks(root):
    if os.path.isfile(root): return [root] if os.path.basename(root) in LOCKS else []
    out = []
    for d, ds, fs in os.walk(root):
        ds[:] = [x for x in ds if x not in SKIP]
        out += [os.path.join(d, f) for f in fs if f in LOCKS]
    return sorted(out)
def _osv(b, lock, t):
    r = subprocess.run([b, "scan", "source", "--format", "json", "-L", lock], capture_output=True, text=True, timeout=t)
    d = json.loads(r.stdout or "{}"); out = []
    for res in d.get("results") or []:
        for p in res.get("packages", []):
            ids = sorted({v["id"] for v in p.get("vulnerabilities", [])})
            if ids: out.append((p["package"]["name"], p["package"]["version"], ids))
    return out
def _trivy(b, lock, t):
    env = dict(os.environ, TRIVY_CACHE_DIR=os.path.expanduser("~/.cyberswarm-tools/trivy-cache"))
    r = subprocess.run([b, "fs", "--scanners", "vuln", "-q", "--skip-db-update", "-f", "json", os.path.dirname(lock) or "."],
                       capture_output=True, text=True, timeout=t, env=env)
    agg = {}
    for res in json.loads(r.stdout or "{}").get("Results") or []:
        for v in res.get("Vulnerabilities") or []: agg.setdefault((v["PkgName"], v["InstalledVersion"]), set()).add(v["VulnerabilityID"])
    return [(n, ver, sorted(i)) for (n, ver), i in agg.items()]
def _grype(b, lock, t):
    env = dict(os.environ, GRYPE_DB_CACHE_DIR=os.path.expanduser("~/.cyberswarm-tools/grype-db"), GRYPE_DB_AUTO_UPDATE="false")
    r = subprocess.run([b, "file:" + lock, "-o", "json", "-q"], capture_output=True, text=True, timeout=t, env=env)
    agg = {}
    for m in json.loads(r.stdout or "{}").get("matches", []):
        agg.setdefault((m["artifact"]["name"], m["artifact"]["version"]), set()).add(m["vulnerability"]["id"])
    return [(n, ver, sorted(i)) for (n, ver), i in agg.items()]
BACKENDS = [("osv-scanner", _osv), ("trivy", _trivy), ("grype", _grype)]
def locate(lines, name, ver):
    """Linha que prova a versão instalada no lockfile (nome e versão)."""
    for n, l in enumerate(lines, 1):
        if (f'node_modules/{name}"' in l or f'"{name}"' in l or l.strip().startswith(name)) and ver in "".join(lines[n-1:n+3]):
            return n
    for n, l in enumerate(lines, 1):
        if name in l: return n
    return None
@register
class SCAAgent(Agent):
    name = "sca"; kind = "path"
    async def run(self, target): return await asyncio.to_thread(self._run, target)
    def _run(self, target):
        self.scope.check_path(target)
        tool = next(((n, f, which(n)) for n, f in BACKENDS if which(n)), None)
        if not tool: self.log.info("sca: nenhuma ferramenta (osv-scanner/trivy/grype) instalada; pulando"); return []
        tname, fn, b = tool; out = []
        for lock in find_locks(target):
            self.scope.check_path(lock); self.audit.log("tool_exec", agent=self.name, tool=tname, path=lock, online=(tname == "osv-scanner"))
            try: hits = fn(b, lock, int(os.environ.get("CYBERSWARM_SCA_TIMEOUT", "180")))
            except (subprocess.TimeoutExpired, ValueError) as e: self.log.warning(f"sca: {tname} falhou em {lock}: {e}"); continue
            lines = open(lock, errors="ignore").read().splitlines()
            for name, ver, ids in sorted(hits):
                n = locate(lines, name, ver)
                if not n: continue  # sem prova no arquivo -> descartado (regra de evidência)
                out.append(self.finding("sca.vulnerable_dependency", lock, f"{name}@{ver}: {', '.join(ids[:5])}{' …' if len(ids) > 5 else ''} ({tname})",
                                        file_proof(lock, lines, n), detail=f"{name}@{ver}", repro=file_repro(lock, n) + f"; advisory: https://osv.dev/vulnerability/{ids[0]}"))
        return out
