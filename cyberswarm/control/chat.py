"""Chat do Hacker AI no Control. Parser de intenção baseado em regras SEMPRE disponível (sem IA).
Provedores (ollama / OpenAI-compat) só enriquecem módulos/explicação; se falharem, cai no modo regras.
Histórico por cliente (chat_threads / chat_messages)."""
import json, re, time
from urllib.parse import urlparse
from ..providers import get_provider, plan_with_provider, Provider
from ..hacker.planner import MODULES
from ..scope import is_lab
from .worker import LAB
INTENTS = [
    (r"\b(status|andamento|progresso|fila)\b", "status"),
    (r"\b(paus(ar|e)|pause)\b", "pause"),
    (r"\b(cancel(ar|e)|parar|stop)\b", "cancel"),
    (r"\b(aprova|approve)\b", "approve_hint"),
    (r"\b(explica|resumo|o que (achou|encontrou)|resultado)\b", "explain"),
    (r"\b(ajuda|help|o que (você|voce) (faz|pode))\b", "help"),
]
HELP = ("Sou o Hacker AI no CyberSwarm Control. Posso planejar e executar auditorias defensivas "
        "só em laboratório (127.0.0.1) ou em clientes com termo de autorização vigente. "
        "Digite um objetivo (ex.: «verificar cabeçalhos TLS e API do laboratório») ou "
        "«status», «pausar #ID», «cancelar #ID», «explica #ID». Testes ativos fora do lab pedem aprovação.")
def detect_intent(text):
    t = (text or "").strip().lower()
    for rx, name in INTENTS:
        if re.search(rx, t): return name
    return "mission"
def extract_job_id(text):
    m = re.search(r"#?\b(\d{1,8})\b", text or "")
    return int(m.group(1)) if m else None
def extract_url(text):
    m = re.search(r"https?://[^\s\"'<>]+", text or "")
    return m.group(0).rstrip(".,;)") if m else None
class ChatService:
    def __init__(self, store, worker, audit):
        self.store, self.worker, self.audit = store, worker, audit
    def cfg(self): return self.store.get("ai_provider", {"mode": "none", "fallback": ["none"]}) or {"mode": "none"}
    def deterministic(self): return bool(self.store.get("deterministic", False))
    def threads(self, user, client_id=None):
        rows = self.store.q("SELECT * FROM chat_threads ORDER BY updated DESC LIMIT 100")
        return [r for r in rows if self._vis(user, r["client_id"]) and (not client_id or r["client_id"] == client_id)]
    def _vis(self, user, cid): return user["clients"] is None or cid in user["clients"]
    def messages(self, user, tid, limit=200):
        th = self.store.q("SELECT * FROM chat_threads WHERE id=?", (tid,), one=True)
        if not th or not self._vis(user, th["client_id"]): raise KeyError("conversa não encontrada")
        return self.store.q("SELECT id,role,content,meta,created FROM chat_messages WHERE thread_id=? ORDER BY id DESC LIMIT ?", (tid, limit))[::-1], th
    def ensure_thread(self, user, client_id, title=None):
        client_id = client_id or LAB
        if client_id != LAB and not self.store.q("SELECT id FROM clients WHERE id=?", (client_id,), one=True):
            raise ValueError("cliente inexistente")
        if not self._vis(user, client_id): raise PermissionError("cliente fora do seu perfil")
        tid = self.store.x("INSERT INTO chat_threads(client_id,title,created_by,created,updated) VALUES(?,?,?,?,?)",
                           (client_id, (title or "Nova conversa")[:120], user["username"], time.time(), time.time()))
        return tid
    def _add(self, tid, role, content, meta=None):
        self.store.x("INSERT INTO chat_messages(thread_id,role,content,meta,created) VALUES(?,?,?,?,?)",
                     (tid, role, content[:8000], json.dumps(meta or {}, ensure_ascii=False), time.time()))
        self.store.x("UPDATE chat_threads SET updated=? WHERE id=?", (time.time(), tid))
    def handle(self, user, tid, text):
        msgs, th = self.messages(user, tid)
        text = (text or "").strip()[:2000]
        if not text: raise ValueError("mensagem vazia")
        self._add(tid, "user", text); intent = detect_intent(text)
        if intent == "help":
            reply = HELP; meta = {"intent": intent}
        elif intent == "status":
            jobs = [j for j in self.store.q("SELECT id,status,goal,client_id FROM jobs ORDER BY id DESC LIMIT 12") if self._vis(user, j["client_id"])]
            reply = "Fila recente:\n" + ("\n".join(f"#{j['id']} [{j['status']}] {j['goal'][:80]}" for j in jobs) or "nenhuma tarefa")
            meta = {"intent": intent, "jobs": [j["id"] for j in jobs]}
        elif intent in ("pause", "cancel"):
            jid = extract_job_id(text)
            if not jid: reply, meta = "Informe o número da tarefa, ex.: pausar #3", {"intent": intent}
            else:
                try:
                    st = self.worker.pause(user, jid) if intent == "pause" else self.worker.cancel(user, jid)
                    reply, meta = f"Tarefa #{jid}: {st}", {"intent": intent, "job": jid, "status": st}
                except Exception as e: reply, meta = f"Não foi possível: {e}", {"intent": intent, "error": str(e)}
        elif intent == "approve_hint":
            pend = [a for a in self.store.q("SELECT id,job_id,target FROM approvals WHERE status='pendente'") if self._vis(user, a.get("client_id", ""))]
            reply = ("Há aprovações pendentes: " + ", ".join(f"#{a['id']} (tarefa {a['job_id']} → {a['target']})" for a in pend) +
                     ". Abra Aprovações no menu para decidir com justificativa.") if pend else "Nenhuma aprovação pendente."
            meta = {"intent": intent, "approvals": [a["id"] for a in pend]}
        elif intent == "explain":
            jid = extract_job_id(text)
            if not jid: reply, meta = "Informe a tarefa, ex.: explica #3", {"intent": intent}
            else:
                j = self.store.q("SELECT * FROM jobs WHERE id=?", (jid,), one=True)
                if not j or not self._vis(user, j["client_id"]): reply, meta = "Tarefa não encontrada", {"intent": intent}
                else:
                    summ = json.loads(j["summary"] or "{}"); plan = json.loads(j["plan_json"] or "{}") or {"modules": summ.get("modules", [])}
                    prov = get_provider(self.cfg(), deterministic=self.deterministic())
                    reply = prov.explain(plan if plan.get("modules") else {"modules": summ.get("modules", []), "tasks": [], "skipped": summ.get("skipped", [])}, summ)
                    meta = {"intent": intent, "job": jid, "provider": prov.name}
        else:  # mission
            reply, meta = self._mission(user, th, text)
        self._add(tid, "assistant", reply, meta); self.audit.log("chat_message", thread=tid, by=user["username"], intent=meta.get("intent"), client=th["client_id"])
        return {"reply": reply, "meta": meta}
    def _mission(self, user, th, text):
        if user["role"] != "owner": return "Perfil somente leitura: peça a um owner para criar missões.", {"intent": "mission", "denied": True}
        cid = th["client_id"]; url = extract_url(text); lab = cid == LAB
        if not lab and not url: return "Para cliente real, informe a URL no escopo (ex.: https://www.exemplo.com.br).", {"intent": "mission", "need_url": True}
        targets = {"lab": True} if lab else {"url": url}
        # se lab e o usuário mencionou validação externa
        kind = "extval" if lab and re.search(r"\b(valida(r|ção)\s+externa|extval|juice|vampi|dvga|webgoat|insecurebank)\b", text.lower()) else "hacker"
        lab_name = None
        if kind == "extval":
            for n in ("juice-shop", "webgoat", "vampi", "dvga", "insecurebankv2"):
                if n.replace("-", " ") in text.lower() or n in text.lower(): lab_name = n; break
            lab_name = lab_name or "juice-shop"
        det = self.deterministic()
        cfg = self.cfg()
        try:
            if kind == "hacker":
                if lab:
                    # plano preliminar só para explicar; o worker cria o job de verdade
                    P, prov = plan_with_provider(text, {"url": "http://127.0.0.1:0", "https": "https://127.0.0.1:0",
                                                        "spec": "x", "iac": "x", "manifest": "x", "plist": "x", "code": "x", "ai": "x", "tcp": "tcp://127.0.0.1"}, True, cfg, det)
                else:
                    P, prov = plan_with_provider(text, targets, False, cfg, det)
                explanation = Provider().explain(P) if det else prov.explain(P)
                # tarefas ativas fora do lab → aviso
                active = [t for t in P["tasks"] if t.get("active") and t.get("target") and not is_lab(t["target"])]
                note = f"\n⚠️ {len(active)} tarefa(s) ativa(s) vão pedir sua aprovação antes de rodar." if active else ""
                jid = self.worker.create(user, "hacker", cid, text, url if not lab else None, None, plan=P, chat_id=th["id"])
                return f"Missão #{jid} criada (provedor: {prov.name}).\n{explanation}{note}\nAcompanhe em Tarefas ou diga «status».", {"intent": "mission", "job": jid, "provider": prov.name, "plan": {"modules": P["modules"], "skipped": P["skipped"]}}
            else:
                jid = self.worker.create(user, "extval", LAB, text, None, lab_name, chat_id=th["id"])
                return f"Validação externa #{jid} enfileirada no laboratório {lab_name}.", {"intent": "mission", "job": jid, "lab": lab_name}
        except Exception as e:
            return f"Não consegui criar a missão: {e}", {"intent": "mission", "error": str(e)}
