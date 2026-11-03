"""Code Security (SAST) module. Tool chosen by Hacker AI selector (ctx.options['tools']['codesec']):
bandit | semgrep (local rules, offline, --metrics off) | builtin (stdlib AST). Falls back to builtin if the tool fails."""
import ast, asyncio, json, os, shutil, subprocess
from ..registry import Agent, register
from .common import file_proof, file_repro
from .code import iter_files
from ..tools import which
RULES = os.path.join(os.path.dirname(os.path.dirname(__file__)), "hacker", "data", "semgrep_rules.yml")
BANDIT_MAP = {"B307": "codesec.eval", "B102": "codesec.eval", "B602": "codesec.shell", "B604": "codesec.shell", "B605": "codesec.shell",
              "B301": "codesec.pickle", "B302": "codesec.pickle", "B506": "codesec.yaml_load", "B303": "codesec.weak_hash", "B324": "codesec.weak_hash",
              "B501": "codesec.tls_verify_off", "B608": "codesec.sql_concat", "B201": "codesec.debug"}
def _name(n):
    if isinstance(n, ast.Name): return n.id
    if isinstance(n, ast.Attribute): return f"{_name(n.value)}.{n.attr}"
    return ""
def ast_scan(src):
    """Returns [(line, check_id)] from builtin AST rules."""
    out = []
    try: tree = ast.parse(src)
    except SyntaxError: return out
    for n in ast.walk(tree):
        if isinstance(n, ast.Call):
            f = _name(n.func); kw = {k.arg: k.value for k in n.keywords}
            if f in ("eval", "exec"): out.append((n.lineno, "codesec.eval"))
            if f.startswith("subprocess.") and isinstance(kw.get("shell"), ast.Constant) and kw["shell"].value is True: out.append((n.lineno, "codesec.shell"))
            if f in ("pickle.loads", "pickle.load", "marshal.loads"): out.append((n.lineno, "codesec.pickle"))
            if f == "yaml.load" and "Loader" not in kw: out.append((n.lineno, "codesec.yaml_load"))
            if f in ("hashlib.md5", "hashlib.sha1"): out.append((n.lineno, "codesec.weak_hash"))
            if isinstance(kw.get("verify"), ast.Constant) and kw["verify"].value is False: out.append((n.lineno, "codesec.tls_verify_off"))
            if f.endswith(".execute") and n.args and isinstance(n.args[0], (ast.BinOp, ast.JoinedStr)) or \
               (f.endswith(".execute") and n.args and isinstance(n.args[0], ast.Call) and _name(n.args[0].func).endswith("format")):
                out.append((n.lineno, "codesec.sql_concat"))
        if isinstance(n, ast.Assign) and any(isinstance(t, ast.Name) and t.id == "DEBUG" for t in n.targets) and isinstance(n.value, ast.Constant) and n.value.value is True:
            out.append((n.lineno, "codesec.debug"))
    return out
def bandit_scan(path):
    exe = which("bandit")
    r = subprocess.run([exe, "-q", "-f", "json", "-r", path], capture_output=True, text=True, timeout=120)
    data = json.loads(r.stdout or "{}")
    if "results" not in data: raise RuntimeError(f"bandit sem saída JSON: {r.stderr[:200]}")
    return [(x["filename"], x["line_number"], BANDIT_MAP.get(x["test_id"], "codesec.external"), x["test_id"]) for x in data["results"]]
def semgrep_scan(path):
    exe = which("semgrep")
    r = subprocess.run([exe, "--config", RULES, "--json", "--metrics", "off", "--quiet", "--disable-version-check", path],
                       capture_output=True, text=True, timeout=300, env={**os.environ, "SEMGREP_SEND_METRICS": "off"})
    data = json.loads(r.stdout or "{}")
    if "results" not in data: raise RuntimeError(f"semgrep sem saída JSON: {r.stderr[:200]}")
    return [(x["path"], x["start"]["line"], x["check_id"].split(".")[-1].replace("-", "_").replace("codesec_", "codesec."), "semgrep") for x in data["results"]]
@register
class CodeSecAuditor(Agent):
    name = "codesec"; kind = "path"
    async def run(self, target): return await asyncio.to_thread(self._run, target)
    def _run(self, target):
        self.scope.check_path(target)
        tool = (self.ctx.options.get("tools") or {}).get("codesec", "builtin"); used = tool; hits = []
        if tool in ("bandit", "semgrep"):
            try:
                hits = (bandit_scan if tool == "bandit" else semgrep_scan)(target)
                self.audit.log("external_tool", agent=self.name, tool=tool, target=target, results=len(hits))
            except Exception as e:
                self.audit.log("tool_fallback", agent=self.name, tool=tool, error=repr(e)[:200]); used = "builtin"; hits = []
        if used == "builtin":
            for p in iter_files(target, (".py",)):
                self.scope.check_path(p); self.audit.log("read_file", agent=self.name, path=p)
                hits += [(p, ln, cid, "ast") for ln, cid in ast_scan(open(p, errors="ignore").read())]
        self.ctx.options.setdefault("tool_used", {})[self.name] = used
        out, cache = [], {}
        for p, ln, cid, rule in hits:
            p = os.path.realpath(p); self.scope.check_path(p)
            if cid not in __import__("cyberswarm.checks", fromlist=["C"]).C: cid = "codesec.external"
            lines = cache.setdefault(p, open(p, errors="ignore").read().splitlines())
            out.append(self.finding(cid, p, f"linha {ln}", file_proof(p, lines, ln), f"{used}:{rule}", file_repro(p, ln)))
        return out
