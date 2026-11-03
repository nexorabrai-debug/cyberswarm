"""AI Security module: static review of prompt templates and LLM agent configs (no model calls).
Optional garak hook (OFF by default; needs CYBERSWARM_GARAK=1, garak installed and a LOCAL model) - not run in tests."""
import asyncio, json, os, re
from ..registry import Agent, register
from .common import file_proof, file_repro, find_line
from .code import iter_files
from .secrets import scan_text, mask
INPUT_VARS = re.compile(r"\{\{?\s*(user_input|input|question|query|message)\s*\}?\}")
DELIM = re.compile(r"<(user|input|data)>|```|\"\"\"|treat .* as data", re.I)
INTERNAL = re.compile(r"(internal|interno|staff|discount|admin|desconto)", re.I)
NO_REVEAL = re.compile(r"(never|não|nao) (reveal|revele|share)", re.I)
@register
class AISecAuditor(Agent):
    name = "aisec"; kind = "path"
    async def run(self, target): return await asyncio.to_thread(self._run, target)
    def _run(self, target):
        self.scope.check_path(target); out = []
        for p in iter_files(target, (".txt", ".md", ".prompt", ".json", ".yaml", ".yml", ".j2")):
            self.scope.check_path(p); self.audit.log("read_file", agent=self.name, path=p)
            text = open(p, errors="ignore").read(); lines = text.splitlines()
            for cid, n, val, masked in scan_text(text):
                out.append(self.finding("ai.secret_in_prompt", p, f"segredo ({cid}) mascarado {mask(val)}", file_proof(p, lines, n, masked), repro=file_repro(p, n)))
            m = INPUT_VARS.search(text)
            if m and not DELIM.search(text):
                n = find_line(lines, m.group(0))
                out.append(self.finding("ai.prompt_injection", p, f"variável {m.group(0)} inserida sem delimitação", file_proof(p, lines, n), repro=file_repro(p, n)))
            if m and INTERNAL.search(text) and not NO_REVEAL.search(text):
                n = find_line(lines, INTERNAL.search(text).group(0))
                out.append(self.finding("ai.system_prompt_disclosure", p, "dados internos no prompt sem instrução de sigilo", file_proof(p, lines, n), repro=file_repro(p, n)))
            if p.endswith(".json"):
                try: cfg = json.loads(text)
                except ValueError: continue
                for t in cfg.get("tools", []):
                    if t.get("enabled") and t.get("type") in ("shell", "exec", "code_exec"):
                        n = find_line(lines, f'"{t["name"]}"')
                        out.append(self.finding("ai.dangerous_tool", p, f"ferramenta {t['name']} ({t['type']}) habilitada", file_proof(p, lines, n), t["name"], file_repro(p, n)))
                if cfg.get("output_filter") is False:
                    n = find_line(lines, '"output_filter"')
                    out.append(self.finding("ai.no_output_filter", p, "output_filter=false", file_proof(p, lines, n), repro=file_repro(p, n)))
        return out
