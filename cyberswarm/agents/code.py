"""Code auditor: secret scanning over a source directory (static, read-only)."""
import asyncio, os
from ..registry import Agent, register
from .secrets import scan_text, mask
from .common import file_proof, file_repro
SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv"}
def iter_files(target, exts=None):
    if os.path.isfile(target): yield target; return
    for root, dirs, fs in os.walk(target):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for f in sorted(fs):
            if exts is None or f.endswith(exts): yield os.path.join(root, f)
def secret_findings(agent, path):
    try: text = open(path, encoding="utf-8").read()
    except (UnicodeDecodeError, OSError): return []
    lines = text.splitlines(); out = []
    for cid, n, val, masked in scan_text(text):
        out.append(agent.finding(cid, path, f"valor mascarado {mask(val)}", file_proof(path, lines, n, masked), repro=file_repro(path, n)))
    return out
@register
class CodeAuditor(Agent):
    name = "code"; kind = "path"
    async def run(self, target): return await asyncio.to_thread(self._run, target)
    def _run(self, target):
        self.scope.check_path(target); out = []
        for p in iter_files(target):
            self.scope.check_path(p); self.audit.log("read_file", agent=self.name, path=p)
            if os.path.getsize(p) > 2_000_000: continue
            out += secret_findings(self, p)
        return out
