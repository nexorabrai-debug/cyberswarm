"""Modo determinístico (sem LLM). Operações simples (só tarefas passivas/estáticas) rodam direto.
Operações complexas (qualquer tarefa ativa de rede ou exploit) só rodam se o plano EXATO estiver pré-aprovado:
sha256 canônico do plano (agente, alvo, ativo, deps) presente em preapproved_plans.json, não expirado, com approved_by.
Mesma entrada -> mesmo plano -> mesmo hash (testado). Nunca chama modelo, mesmo que um adaptador esteja configurado."""
import hashlib, json, os, time
def canonical(tasks):
    return [{"agent": t["agent"], "target": t["target"], "active": bool(t.get("active")), "kind": t.get("kind", "scan"),
             "deps": sorted(t.get("deps", []))} for t in sorted(tasks, key=lambda t: t["id"])]
def plan_hash(tasks): return hashlib.sha256(json.dumps(canonical(tasks), sort_keys=True).encode()).hexdigest()
def is_complex(tasks): return any(t.get("active") or t.get("kind") == "exploit" or t.get("agent") == "exploitlab" for t in tasks)
class DeterministicGate:
    def __init__(self, path, audit):
        self.path, self.audit = path, audit
    def _load(self):
        if not os.path.exists(self.path): return []
        return json.load(open(self.path)).get("plans", [])
    def check(self, tasks, client_id=None):
        """Retorna (permitido, motivo). Registra a decisão na auditoria."""
        h = plan_hash(tasks)
        if not is_complex(tasks): ok, why = True, "simples (sem tarefa ativa)"
        else:
            m = [p for p in self._load() if p.get("plan_sha256") == h and p.get("approved_by") and p.get("expires", 0) > time.time()
                 and (p.get("client_id") in (None, client_id))]
            ok, why = (True, f"pré-aprovado por {m[0]['approved_by']}") if m else (False, "operação complexa sem plano pré-aprovado")
        self.audit.log("deterministic_gate", plan=h, allowed=ok, reason=why, client=client_id)
        return ok, why, h
