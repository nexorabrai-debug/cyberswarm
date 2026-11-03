"""Cloud auditor: static scan of local Terraform / JSON / YAML (no cloud API calls)."""
import asyncio, re
from ..registry import Agent, register
from .common import file_proof, file_repro
from .code import iter_files, secret_findings
ADMIN_PORTS = {"22", "3389", "3306", "5432", "1433", "6379", "27017", "9200"}
@register
class CloudAuditor(Agent):
    name = "cloud"; kind = "path"
    async def run(self, target): return await asyncio.to_thread(self._run, target)
    def _run(self, target):
        self.scope.check_path(target); out = []
        for p in iter_files(target, (".tf", ".tfvars", ".json", ".yaml", ".yml")):
            self.scope.check_path(p); self.audit.log("read_file", agent=self.name, path=p)
            lines = open(p, errors="ignore").read().splitlines(); port = None; resource = "?"
            for n, line in enumerate(lines, 1):
                r = re.match(r'\s*resource\s+"([^"]+)"\s+"([^"]+)"', line)
                if r: resource, port = f"{r.group(1)}.{r.group(2)}", None
                m = re.search(r"from_port\s*=\s*(\d+)", line)
                if m: port = m.group(1)
                if re.search(r'acl\s*=\s*"public-read(-write)?"', line):
                    out.append(self.finding("cloud.s3_public_acl", p, f"{resource}: {line.strip()}", file_proof(p, lines, n), detail=resource, repro=file_repro(p, n)))
                if re.search(r"block_public_(acls|policy)\s*=\s*false", line):
                    out.append(self.finding("cloud.s3_block_disabled", p, f"{resource}: {line.strip()}", file_proof(p, lines, n), detail=resource, repro=file_repro(p, n)))
                if "0.0.0.0/0" in line:
                    cid = "cloud.sg_admin_open" if port in ADMIN_PORTS else "cloud.sg_open"
                    out.append(self.finding(cid, p, f"{resource}: porta {port or '?'} aberta para 0.0.0.0/0", file_proof(p, lines, n),
                                            detail=f"{resource} porta {port or '?'}", repro=file_repro(p, n)))
            out += secret_findings(self, p)
        return out
