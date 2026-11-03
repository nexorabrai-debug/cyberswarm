"""Message bus between agents. Every message follows the JSON schema in docs/INTERFACES.md (validated here)."""
import itertools, json, threading, time
TYPES = {"task", "task_result", "finding", "hypothesis", "verification", "tool_selection", "approval", "error", "metric", "plan"}
REQUIRED = {"id": int, "ts": float, "type": str, "sender": str, "recipient": str, "run_id": (int, type(None)), "payload": dict}
SCHEMA = {"$schema": "https://json-schema.org/draft/2020-12/schema", "title": "CyberSwarm Hacker AI message", "type": "object",
          "required": list(REQUIRED), "additionalProperties": False,
          "properties": {"id": {"type": "integer"}, "ts": {"type": "number"}, "type": {"enum": sorted(TYPES)},
                         "sender": {"type": "string"}, "recipient": {"type": "string", "description": "agent name or '*'"},
                         "run_id": {"type": ["integer", "null"]}, "payload": {"type": "object"}}}
class InvalidMessage(ValueError): pass
def validate_message(m):
    if set(m) != set(REQUIRED): raise InvalidMessage(f"campos {sorted(set(m) ^ set(REQUIRED))}")
    for k, t in REQUIRED.items():
        if not isinstance(m[k], t): raise InvalidMessage(f"campo {k} com tipo inválido")
    if m["type"] not in TYPES: raise InvalidMessage(f"tipo {m['type']} desconhecido")
    json.dumps(m)  # must be JSON-serializable
    return m
class Bus:
    def __init__(self, run_id=None, memory=None):
        self.run_id, self.memory = run_id, memory; self.subs = {}; self.log = []; self._ids = itertools.count(1); self.lock = threading.Lock()
    def subscribe(self, mtype, fn): self.subs.setdefault(mtype, []).append(fn)
    def publish(self, mtype, sender, payload, recipient="*"):
        with self.lock:
            m = validate_message({"id": next(self._ids), "ts": time.time(), "type": mtype, "sender": sender, "recipient": recipient, "run_id": self.run_id, "payload": payload})
            self.log.append(m)
        if self.memory: self.memory.add_message(m)
        for fn in self.subs.get(mtype, []) + self.subs.get("*", []): fn(m)
        return m
    def of(self, mtype): return [m for m in self.log if m["type"] == mtype]
