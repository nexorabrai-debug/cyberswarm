"""Deterministic rule-based planner: goal (pt-BR/en text, or YAML/JSON) -> task DAG mapped to modules.
Optional LOCAL LLM hook (Ollama) - OFF by default (CYBERSWARM_LLM=ollama). The LLM can only ADD modules from the known
list; it never chooses targets, never removes safety steps, and the plan is still validated by the same rules."""
import json, os, re, urllib.request
MODULES = {  # module -> (agent, target_kind, active_network)
    "web": ("web", "url", True), "tls": ("tls", "https", True), "api": ("api", "spec", False), "cloud": ("cloud", "iac", False),
    "android": ("mobile", "manifest", False), "ios": ("ios", "plist", False), "secrets": ("code", "code", False),
    "codesec": ("codesec", "code", False), "network": ("network", "tcp", True), "aisec": ("aisec", "ai", False),
    "exploitlab": ("exploitlab", "url", True)}
ANALYSIS = ["verification", "threatintel", "vulnresearch", "metrics", "report"]
KEYWORDS = [(r"\b(complet[oa]|full|tud[oa]|todos?)\b", list(MODULES)),
            (r"\b(web|site|http)\b", ["web"]), (r"\b(tls|ssl|https|certificad\w*)\b", ["tls"]), (r"\bapis?\b", ["api"]),
            (r"\b(cloud|nuvem|terraform|iac)\b", ["cloud"]), (r"\b(android|mobile|celular|app)\b", ["android"]),
            (r"\b(ios|iphone|ipad)\b", ["ios"]), (r"\b(c[oó]digo|code|sast|fonte)\b", ["codesec", "secrets"]),
            (r"\b(segredos?|secrets?|credenciais?)\b", ["secrets"]), (r"\b(rede|network|portas?|ports?)\b", ["network"]),
            (r"\b(ia|ai|llm|prompts?|ml)\b", ["aisec"]), (r"\b(exploit|poc|explora\w*)\b", ["exploitlab", "web"])]
def parse_goal(goal):
    """Accepts free text or a YAML/JSON document / file path. Returns dict(text, modules, targets)."""
    if isinstance(goal, dict): return {"text": goal.get("goal", ""), "modules": goal.get("modules"), "targets": goal.get("targets", {})}
    if os.path.isfile(goal):
        raw = open(goal).read()
        try: return parse_goal(json.loads(raw))
        except ValueError: pass
        try:
            import yaml; return parse_goal(yaml.safe_load(raw))
        except Exception: return parse_goal(_mini_yaml(raw))
    s = goal.strip()
    if s.startswith("{"): return parse_goal(json.loads(s))
    if re.match(r"(?m)^(goal|modules)\s*:", s): return parse_goal(_mini_yaml(s))
    return {"text": s, "modules": None, "targets": {}}
def _mini_yaml(raw):
    """Tiny YAML subset (key: value, key: [a, b], '- item' lists, one nesting level) for when PyYAML is absent."""
    out, cur = {}, None
    for line in raw.splitlines():
        if not line.strip() or line.strip().startswith("#"): continue
        m = re.match(r"^(\s*)(-\s+)?([\w.-]+)?\s*:?\s*(.*)$", line); ind, dash, key, val = len(m.group(1)), m.group(2), m.group(3), m.group(4).strip()
        if dash and cur: (out[cur] if isinstance(out[cur], list) else out.setdefault(cur, [])).append((key or val).strip()); continue
        v = [x.strip() for x in val.strip("[]").split(",") if x.strip()] if val.startswith("[") else val.strip("'\"")
        if ind == 0: out[key] = v if val else []; cur = key
        elif cur:
            if isinstance(out[cur], list) and not out[cur]: out[cur] = {}
            out[cur][key] = v
    return out
def llm_suggest(text):
    """Optional local LLM hook. OFF unless CYBERSWARM_LLM=ollama. Returns [] on any problem (graceful)."""
    if os.environ.get("CYBERSWARM_LLM") != "ollama": return []
    model = os.environ.get("CYBERSWARM_LLM_MODEL", "llama3.2"); prompt = f"Liste, separados por vírgula, apenas módulos desta lista relevantes ao objetivo: {', '.join(MODULES)}. Objetivo: {text}"
    try:
        req = urllib.request.Request("http://127.0.0.1:11434/api/generate", data=json.dumps({"model": model, "prompt": prompt, "stream": False}).encode(), headers={"Content-Type": "application/json"})
        resp = json.loads(urllib.request.urlopen(req, timeout=20).read()).get("response", "")
    except Exception: return []
    return [m for m in MODULES if re.search(rf"\b{m}\b", resp.lower())]
def select_modules(text):
    t = text.lower(); mods = []
    for rx, ms in KEYWORDS:
        if re.search(rx, t): mods += [m for m in ms if m not in mods]
    return mods or ["web", "tls"]
def plan(goal, targets, lab=True):
    """targets: {'url','https','spec','iac','manifest','plist','code','ai','tcp'} -> list of tasks with deps (a DAG).
    Modules without a target are skipped with a reason (never guessed). exploitlab is LAB-ONLY and hypothesis-driven."""
    g = parse_goal(goal); targets = {**targets, **(g["targets"] or {})}
    mods = list(g["modules"]) if g["modules"] else select_modules(g["text"])
    for m in llm_suggest(g["text"]):
        if m not in mods: mods.append(m)
    tasks, skipped, n = [], [], 0
    def add(module, agent, target, deps=(), kind="scan", active=False, condition=None):
        nonlocal n; n += 1; tid = f"T{n:02d}"
        tasks.append({"id": tid, "module": module, "agent": agent, "target": target, "deps": list(deps), "kind": kind, "active": active, "condition": condition}); return tid
    scan_ids = []
    for m in mods:
        if m not in MODULES: skipped.append((m, "módulo desconhecido")); continue
        agent, tk, active = MODULES[m]
        if m == "exploitlab": continue
        if m == "web":
            for k in ("url", "https"):
                if targets.get(k): scan_ids.append(add(m, agent, targets[k], active=True))
            if not (targets.get("url") or targets.get("https")): skipped.append((m, "sem alvo URL"))
            continue
        if not targets.get(tk): skipped.append((m, f"sem alvo '{tk}'")); continue
        if m == "network" and not lab: skipped.append((m, "rede: somente laboratório 127.0.0.1")); continue
        scan_ids.append(add(m, agent, targets[tk], active=active))
    exploit_ids = []
    if "exploitlab" in mods:
        web_ids = [t["id"] for t in tasks if t["module"] == "web" and t["target"] == targets.get("url")]
        if lab and web_ids: exploit_ids.append(add("exploitlab", "exploitlab", targets["url"], web_ids, active=True,
                                                    condition="hipótese: web encontrou web.exposed.* ou web.cors.reflect_creds"))
        else: skipped.append(("exploitlab", "somente laboratório 127.0.0.1 e com alvo web HTTP"))
    v = add("verification", None, None, scan_ids + exploit_ids, "analysis")
    ti = add("threatintel", None, None, [v], "analysis"); vr = add("vulnresearch", None, None, [v, ti], "analysis")
    mt = add("metrics", None, None, [vr], "analysis") if lab else None
    add("report", None, None, [x for x in (vr, mt) if x], "analysis")
    return {"goal": g["text"], "modules": mods, "tasks": tasks, "skipped": skipped, "levels": levels(tasks)}
def levels(tasks):
    """Topological layering (Kahn). Raises ValueError on cycles."""
    deps = {t["id"]: set(t["deps"]) for t in tasks}; done, out = set(), []
    while len(done) < len(deps):
        layer = sorted(t for t, d in deps.items() if t not in done and d <= done)
        if not layer: raise ValueError("ciclo no plano")
        out.append(layer); done |= set(layer)
    return out
