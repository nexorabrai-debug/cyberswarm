"""Camada de provedores de IA — independente do Grok. Padrão: none (só regras).
Chaves ficam só no servidor (env CYBERSWARM_AI_KEY_* ou settings criptografados com CYBERSWARM_SECRET).
O modelo só SUGERE módulos da lista conhecida; o plano passa pelo escopo, ApprovalGate e DeterministicGate."""
import base64, hashlib, json, os, re, urllib.error, urllib.request
from .hacker.planner import MODULES, select_modules, plan as make_plan
KNOWN = list(MODULES)
def _fernet():
    try:
        from cryptography.fernet import Fernet
        sec = os.environ.get("CYBERSWARM_SECRET", "").encode() or b"cyberswarm-dev-only-change-me"
        key = base64.urlsafe_b64encode(hashlib.sha256(sec).digest()); return Fernet(key)
    except Exception: return None
def encrypt_secret(plain):
    f = _fernet()
    if not f or not plain: return ""
    return f.encrypt(plain.encode()).decode()
def decrypt_secret(tok):
    f = _fernet()
    if not f or not tok: return ""
    try: return f.decrypt(tok.encode()).decode()
    except Exception: return ""
class Provider:
    name = "none"
    def available(self): return True
    def suggest_modules(self, text, known=KNOWN): return select_modules(text)
    def explain(self, plan, findings_summary=None):
        mods = ", ".join(plan.get("modules") or [])
        n = len([t for t in plan.get("tasks", []) if t.get("kind") == "scan"])
        skip = "; ".join(f"{a} ({b})" for a, b in plan.get("skipped") or []) or "nenhum"
        base = f"Plano com módulos: {mods}. {n} tarefas de varredura. Ignorados: {skip}."
        if findings_summary is not None:
            base += f" Resultado: {findings_summary.get('findings', 0)} achados, {findings_summary.get('confirmed', 0)} confirmados."
        return base
class OllamaProvider(Provider):
    name = "ollama"
    def __init__(self, base_url=None, model=None):
        self.base = (base_url or os.environ.get("OLLAMA_URL") or "http://127.0.0.1:11434").rstrip("/")
        self.model = model or os.environ.get("OLLAMA_MODEL") or "llama3.2"
    def available(self):
        if not self.base.startswith(("http://127.0.0.1", "http://localhost", "https://127.0.0.1")): return False
        try:
            urllib.request.urlopen(self.base + "/api/tags", timeout=2); return True
        except Exception: return False
    def _gen(self, prompt, timeout=25):
        body = json.dumps({"model": self.model, "prompt": prompt, "stream": False}).encode()
        return json.loads(urllib.request.urlopen(urllib.request.Request(self.base + "/api/generate", body, {"Content-Type": "application/json"}), timeout=timeout).read()).get("response", "")
    def suggest_modules(self, text, known=KNOWN):
        try:
            resp = self._gen(f"Módulos: {', '.join(known)}. Objetivo: {text[:500]}. Responda só nomes de módulos separados por vírgula.")
            got = [m for m in known if re.search(rf"\b{re.escape(m)}\b", resp.lower())]
            return got or select_modules(text)
        except Exception: return select_modules(text)
    def explain(self, plan, findings_summary=None):
        try:
            return self._gen("Explique em português do Brasil, em até 6 frases, este plano de auditoria defensiva: " + json.dumps({"modules": plan.get("modules"), "skipped": plan.get("skipped"), "resumo": findings_summary}, ensure_ascii=False)[:1500]) or super().explain(plan, findings_summary)
        except Exception: return super().explain(plan, findings_summary)
class OpenAICompatProvider(Provider):
    name = "openai"
    def __init__(self, base_url=None, api_key=None, model=None):
        self.base = (base_url or os.environ.get("CYBERSWARM_AI_BASE") or "").rstrip("/")
        self.key = api_key or os.environ.get("CYBERSWARM_AI_KEY") or ""
        self.model = model or os.environ.get("CYBERSWARM_AI_MODEL") or "gpt-4o-mini"
    def available(self): return bool(self.base and self.key and self.base.startswith("https://"))
    def _chat(self, prompt, timeout=30):
        body = json.dumps({"model": self.model, "messages": [{"role": "user", "content": prompt}], "temperature": 0}).encode()
        req = urllib.request.Request(self.base + "/chat/completions", body, {"Content-Type": "application/json", "Authorization": "Bearer " + self.key})
        return json.loads(urllib.request.urlopen(req, timeout=timeout).read())["choices"][0]["message"]["content"]
    def suggest_modules(self, text, known=KNOWN):
        try:
            resp = self._chat(f"Módulos: {', '.join(known)}. Objetivo: {text[:500]}. Responda só nomes.")
            got = [m for m in known if re.search(rf"\b{re.escape(m)}\b", resp.lower())]
            return got or select_modules(text)
        except Exception: return select_modules(text)
    def explain(self, plan, findings_summary=None):
        try:
            return self._chat("Explique em pt-BR (até 6 frases) este plano defensivo: " + json.dumps({"modules": plan.get("modules"), "resumo": findings_summary}, ensure_ascii=False)[:1500]) or super().explain(plan, findings_summary)
        except Exception: return super().explain(plan, findings_summary)
def chain_from_settings(cfg):
    """cfg: {mode, base_url, model, api_key_enc, fallback:['none','ollama','openai']} — monta a cadeia com fallback."""
    mode = (cfg or {}).get("mode") or os.environ.get("CYBERSWARM_MODEL", "none")
    fb = (cfg or {}).get("fallback") or ["none"]
    providers = []
    order = [mode] + [x for x in fb if x != mode]
    for name in order:
        if name == "ollama": providers.append(OllamaProvider((cfg or {}).get("base_url"), (cfg or {}).get("model")))
        elif name == "openai":
            key = decrypt_secret((cfg or {}).get("api_key_enc", "")) or os.environ.get("CYBERSWARM_AI_KEY", "")
            providers.append(OpenAICompatProvider((cfg or {}).get("base_url"), key, (cfg or {}).get("model")))
        else: providers.append(Provider())
    return providers or [Provider()]
def get_provider(cfg=None, deterministic=False):
    if deterministic: return Provider()
    for p in chain_from_settings(cfg):
        if p.available(): return p
    return Provider()
def plan_with_provider(goal_text, targets, lab=True, cfg=None, deterministic=False):
    """Sempre usa o parser de regras; o provedor (se disponível) só adiciona módulos da lista conhecida."""
    p = get_provider(cfg, deterministic=deterministic)
    mods = select_modules(goal_text)
    if not deterministic and p.name != "none":
        for m in p.suggest_modules(goal_text):
            if m in MODULES and m not in mods: mods.append(m)
    return make_plan({"goal": goal_text, "modules": mods}, targets, lab=lab), p
