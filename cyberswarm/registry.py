"""Agent plugin base class + registry."""
from .checks import C
SEVERITIES = ["info", "low", "medium", "high", "critical"]
REGISTRY = {}
def register(cls):
    REGISTRY[cls.name] = cls; return cls
class Agent:
    """Plugin base. Subclasses set `name`, `kind` ('url'|'path') and implement async run(target)."""
    name = "base"; kind = "url"
    def __init__(self, ctx):
        self.ctx = ctx; self.scope, self.log, self.net, self.audit = ctx.scope, ctx.log, ctx.net, ctx.audit
    def finding(self, check_id, target, evidence, proof=None, detail="", repro=""):
        """proof: {"type":"http","request":..,"response":..} or {"type":"file","path":..,"line":N,"snippet":..}"""
        c = C[check_id]
        return {"agent": self.name, "check_id": check_id, "title": c["title"] + (f": {detail}" if detail else ""),
                "severity": c["severity"], "target": target, "evidence": evidence, "impact": c["impact"],
                "recommendation": c["recommendation"], "refs": c["refs"], "proof": proof or {}, "repro": repro}
    async def run(self, target):
        raise NotImplementedError
def load_all():
    from .agents import web, tls, api, cloud, mobile, ios, code, codesec, network, aisec, exploitlab, sca, labauth  # noqa: F401
    return REGISTRY
