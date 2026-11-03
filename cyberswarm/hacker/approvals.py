"""Approval gate for sensitive operations. DENY BY DEFAULT; every decision goes to the audit trail.
Sensitive ops: active_client_test (active modules against a non-lab target), system_change (e.g. installing tools),
out_of_scope (ALWAYS denied: a token never widens the scope registered in clients.json)."""
import datetime, json, os
from urllib.parse import urlparse
SENSITIVE = {"active_client_test", "system_change", "out_of_scope"}
class ApprovalDenied(PermissionError): pass
def _host(t): return (urlparse(t).hostname or t).lower() if "://" in t else t
class ApprovalGate:
    def __init__(self, path, audit):
        self.path, self.audit = path, audit
    def _load(self):
        if not os.path.exists(self.path): return []
        data = json.load(open(self.path))
        return data.get("approvals", []) if isinstance(data, dict) else []
    def check(self, op, target, token=None, client_id=None):
        """Returns True if allowed. Raises nothing; logs approval_granted / approval_denied."""
        def deny(reason):
            self.audit.log("approval_denied", operation=op, target=target, client=client_id, reason=reason); return False
        if op not in SENSITIVE: return deny("operação desconhecida")
        if op == "out_of_scope": return deny("fora do escopo registrado: aprovação não amplia escopo")
        if not token: return deny("sem token de aprovação")
        for a in self._load():
            if a.get("token") != token: continue
            if a.get("op") != op: return deny("token emitido para outra operação")
            if a.get("target") and _host(a["target"]) != _host(target): return deny("token emitido para outro alvo")
            if client_id and a.get("client_id") and a["client_id"] != client_id: return deny("token de outro cliente")
            try:
                if datetime.date.fromisoformat(a.get("expires", "1970-01-01")) < datetime.date.today(): return deny("token expirado")
            except ValueError: return deny("data de expiração inválida")
            if not a.get("approved_by"): return deny("token sem responsável (approved_by)")
            self.audit.log("approval_granted", operation=op, target=target, client=client_id, approved_by=a["approved_by"]); return True
        return deny("token não encontrado em approvals.json")
    def require(self, op, target, token=None, client_id=None):
        if not self.check(op, target, token, client_id): raise ApprovalDenied(f"operação sensível '{op}' negada para {target}: aprovação explícita ausente/inválida")
