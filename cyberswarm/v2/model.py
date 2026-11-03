"""Interface de adaptador de modelo — DESLIGADO por padrão.
O modelo só pode SUGERIR módulos/ordem; a saída é filtrada para nomes de módulo conhecidos e o plano resultante
passa pelo mesmo escopo, ApprovalGate e DeterministicGate. O modelo nunca executa nada nem vê segredos.
Ativação explícita: CYBERSWARM_MODEL=ollama (local, gratuito; reaproveita o gancho do planner) ou registrar um adaptador."""
import os
class ModelAdapter:
    name = "base"
    def available(self): return False
    def suggest_modules(self, goal_text, known): raise NotImplementedError
class NullAdapter(ModelAdapter):
    name = "off"
    def suggest_modules(self, goal_text, known): return []
class OllamaAdapter(ModelAdapter):
    name = "ollama"
    def available(self): return True
    def suggest_modules(self, goal_text, known):
        import re, urllib.request, json
        url = os.environ.get("OLLAMA_URL", "http://127.0.0.1:11434")
        if not url.startswith(("http://127.0.0.1", "http://localhost")): return []  # só modelo local
        try:
            body = json.dumps({"model": os.environ.get("OLLAMA_MODEL", "llama3"), "stream": False,
                               "prompt": f"Módulos: {', '.join(known)}. Objetivo: {goal_text[:500]}. Responda só nomes de módulos."}).encode()
            resp = json.loads(urllib.request.urlopen(urllib.request.Request(url + "/api/generate", body), timeout=20).read())["response"]
        except Exception: return []
        return [m for m in known if re.search(rf"\b{re.escape(m)}\b", resp.lower())]
ADAPTERS = {"off": NullAdapter, "ollama": OllamaAdapter}
def get_adapter(deterministic=False):
    if deterministic: return NullAdapter()
    return ADAPTERS.get(os.environ.get("CYBERSWARM_MODEL", "off"), NullAdapter)()
