"""Chat de comandos do CyberSwarm Control.
Ordem em português → allow-list → confirmação de escopo → fila de jobs → resultado no chat.
Sem shell livre, sem roubo de credencial, sem alvo fora do escopo autorizado."""
import json, time
from urllib.parse import urlparse
from ..providers import get_provider, plan_with_provider, Provider
from ..scope import is_lab, OutOfScope, client_scope
from .worker import LAB, client_record
from . import commands as CMD

HELP = CMD.help_text()


class ChatService:
    def __init__(self, store, worker, audit):
        self.store, self.worker, self.audit = store, worker, audit

    def cfg(self):
        return self.store.get("ai_provider", {"mode": "none", "fallback": ["none"]}) or {"mode": "none"}

    def deterministic(self):
        return bool(self.store.get("deterministic", False))

    def threads(self, user, client_id=None):
        rows = self.store.q("SELECT * FROM chat_threads ORDER BY updated DESC LIMIT 100")
        return [r for r in rows if self._vis(user, r["client_id"]) and (not client_id or r["client_id"] == client_id)]

    def _vis(self, user, cid):
        return user["clients"] is None or cid in user["clients"]

    def messages(self, user, tid, limit=200):
        th = self.store.q("SELECT * FROM chat_threads WHERE id=?", (tid,), one=True)
        if not th or not self._vis(user, th["client_id"]):
            raise KeyError("conversa não encontrada")
        return self.store.q(
            "SELECT id,role,content,meta,created FROM chat_messages WHERE thread_id=? ORDER BY id DESC LIMIT ?",
            (tid, limit),
        )[::-1], th

    def ensure_thread(self, user, client_id, title=None):
        client_id = client_id or LAB
        if client_id != LAB and not self.store.q("SELECT id FROM clients WHERE id=?", (client_id,), one=True):
            raise ValueError("cliente inexistente")
        if not self._vis(user, client_id):
            raise PermissionError("cliente fora do seu perfil")
        tid = self.store.x(
            "INSERT INTO chat_threads(client_id,title,created_by,created,updated) VALUES(?,?,?,?,?)",
            (client_id, (title or "Nova conversa")[:120], user["username"], time.time(), time.time()),
        )
        return tid

    def _add(self, tid, role, content, meta=None):
        self.store.x(
            "INSERT INTO chat_messages(thread_id,role,content,meta,created) VALUES(?,?,?,?,?)",
            (tid, role, content[:8000], json.dumps(meta or {}, ensure_ascii=False), time.time()),
        )
        self.store.x("UPDATE chat_threads SET updated=? WHERE id=?", (time.time(), tid))

    def _pending_get(self, tid):
        th = self.store.q("SELECT pending FROM chat_threads WHERE id=?", (tid,), one=True) or {}
        raw = th.get("pending")
        if not raw:
            return None
        try:
            return json.loads(raw)
        except Exception:
            return None

    def _pending_set(self, tid, data):
        self.store.x(
            "UPDATE chat_threads SET pending=?, updated=? WHERE id=?",
            (json.dumps(data, ensure_ascii=False) if data else None, time.time(), tid),
        )

    def post_job_result(self, jid):
        """Chamado pelo worker ao concluir/errar: empilha resumo no chat da missão."""
        j = self.store.q("SELECT * FROM jobs WHERE id=?", (jid,), one=True)
        if not j or not j.get("chat_id"):
            return
        tid = j["chat_id"]
        status = j.get("status")
        summ = {}
        try:
            summ = json.loads(j.get("summary") or "{}")
        except Exception:
            summ = {}
        if status == "concluida":
            findings = summ.get("findings") or summ.get("confirmed")
            n = findings if isinstance(findings, int) else (len(findings) if isinstance(findings, list) else summ.get("confirmed", "?"))
            mods = summ.get("modules") or []
            elapsed = summ.get("elapsed_s")
            reply = (
                f"Resultado da tarefa #{jid}: concluída.\n"
                f"Módulos: {', '.join(mods) if isinstance(mods, list) else mods}\n"
                f"Achados/confirmados: {n}"
                + (f" · {elapsed}s" if elapsed is not None else "")
                + "\nVeja Tarefas/Achados para o relatório completo. Nada inventado — só o que a fila registrou."
            )
        elif status == "erro":
            reply = f"Tarefa #{jid} falhou: {(j.get('error') or 'erro')[:400]}"
        else:
            reply = f"Tarefa #{jid} terminou com status «{status}»."
        meta = {"intent": "job_result", "job": jid, "status": status}
        self._add(tid, "assistant", reply, meta)
        self.audit.log("chat_job_result", thread=tid, job=jid, status=status)

    def handle(self, user, tid, text):
        msgs, th = self.messages(user, tid)
        text = (text or "").strip()[:2000]
        if not text:
            raise ValueError("mensagem vazia")
        self._add(tid, "user", text)

        # 1) confirmação / aborto de pedido pendente
        pending = self._pending_get(tid)
        ctrl = CMD.detect_control_intent(text)
        if pending and ctrl == "abort_pending":
            self._pending_set(tid, None)
            reply, meta = "Pedido cancelado. Nada foi executado.", {"intent": "abort_pending"}
            self._add(tid, "assistant", reply, meta)
            self.audit.log("chat_message", thread=tid, by=user["username"], intent="abort_pending", client=th["client_id"])
            return {"reply": reply, "meta": meta}
        if pending and ctrl == "confirm":
            reply, meta = self._launch(user, th, pending, confirmed=True)
            self._pending_set(tid, None)
            self._add(tid, "assistant", reply, meta)
            self.audit.log("chat_message", thread=tid, by=user["username"], intent=meta.get("intent"), client=th["client_id"])
            return {"reply": reply, "meta": meta}

        # 2) parser allow-list
        parsed = CMD.parse_command(text, th["client_id"], LAB)

        if parsed["action"] == "refuse":
            reply, meta = parsed["error"], {"intent": parsed.get("intent") or "refuse"}
        elif parsed["action"] == "none":
            reply, meta = parsed["error"], {"intent": "unknown"}
        elif parsed["action"] == "control":
            reply, meta = self._control(user, th, text, parsed["intent"])
        else:  # propose
            # valida escopo contra cadastro do cliente antes de propor
            ok, err = self._validate_scope(th, parsed)
            if not ok:
                reply, meta = err, {"intent": "out_of_scope"}
            elif parsed.get("inline_confirm"):
                reply, meta = self._launch(user, th, parsed, confirmed=True)
            else:
                reply, meta = self._propose(tid, parsed)

        self._add(tid, "assistant", reply, meta)
        self.audit.log(
            "chat_message",
            thread=tid,
            by=user["username"],
            intent=meta.get("intent"),
            client=th["client_id"],
        )
        return {"reply": reply, "meta": meta}

    def _validate_scope(self, th, parsed):
        """Garante que o alvo está no escopo autorizado do thread/cliente."""
        cid = th["client_id"]
        if parsed.get("kind") == "extval" or parsed.get("lab") or cid == LAB:
            # lab: só 127.0.0.1/localhost
            for h in parsed.get("scope_hosts") or []:
                if h not in ("127.0.0.1", "localhost"):
                    return False, f"Host {h} fora do laboratório."
            return True, None
        url = parsed.get("target_url")
        if not url:
            return False, "Escopo incompleto: informe a URL autorizada."
        row = self.store.q("SELECT * FROM clients WHERE id=?", (cid,), one=True)
        if not row:
            return False, "Cliente sem cadastro de escopo autorizado."
        try:
            sc = client_scope({cid: client_record(row)}, cid)
            sc.check(url)
        except OutOfScope as e:
            return False, f"Alvo fora do escopo autorizado: {e}"
        host = (urlparse(url).hostname or "").lower()
        hosts = json.loads(row["hosts"] or "[]")
        if host not in {h.lower() for h in hosts} and host not in ("127.0.0.1", "localhost"):
            return False, f"Host «{host}» não está no campo de escopo do cliente «{cid}»."
        return True, None

    def _propose(self, tid, parsed):
        pending = {
            "kind": parsed["kind"],
            "goal": parsed["goal"],
            "commands": parsed.get("commands") or [],
            "modules": parsed.get("modules") or [],
            "lab": bool(parsed.get("lab")),
            "lab_name": parsed.get("lab_name"),
            "target_url": parsed.get("target_url"),
            "target_label": parsed.get("target_label"),
            "scope_hosts": parsed.get("scope_hosts") or [],
        }
        self._pending_set(tid, pending)
        cmds = ", ".join(pending["commands"]) or "missão"
        hosts = ", ".join(pending["scope_hosts"]) or "(lab)"
        reply = (
            f"Entendi o comando: {cmds}.\n"
            f"Ação: {parsed.get('kind')} · alvo: {pending['target_label']}\n"
            f"Escopo autorizado proposto (hosts): {hosts}\n"
            f"Objetivo: {pending['goal'][:300]}\n\n"
            "Para eu executar, responda exatamente com «escopo autorizado» (ou «confirmo»).\n"
            "Para desistir: «desistir». Sem confirmação eu não rodo nada."
        )
        meta = {
            "intent": "confirm_scope",
            "pending": True,
            "commands": pending["commands"],
            "scope_hosts": pending["scope_hosts"],
            "target": pending["target_label"],
        }
        return reply, meta

    def _launch(self, user, th, pending, confirmed=False):
        if user["role"] != "owner":
            return "Perfil somente leitura: peça a um owner para criar missões.", {
                "intent": "mission",
                "denied": True,
            }
        if not confirmed:
            return "Confirme o escopo com «escopo autorizado» antes de eu executar.", {
                "intent": "confirm_scope",
                "need_confirm": True,
            }
        # revalida escopo na hora de lançar
        ok, err = self._validate_scope(th, pending)
        if not ok:
            return err, {"intent": "out_of_scope"}

        cid = th["client_id"]
        kind = pending.get("kind") or "hacker"
        goal = pending.get("goal") or "auditoria defensiva"
        url = pending.get("target_url")
        lab_name = pending.get("lab_name")
        det = self.deterministic()
        cfg = self.cfg()
        try:
            if kind == "extval":
                jid = self.worker.create(
                    user, "extval", LAB, goal, None, lab_name or "juice-shop", chat_id=th["id"]
                )
                return (
                    f"Escopo confirmado. Validação externa #{jid} enfileirada no laboratório {lab_name or 'juice-shop'}.\n"
                    "Acompanhe com «status» — o resultado volta neste chat.",
                    {"intent": "mission", "job": jid, "lab": lab_name, "confirmed_scope": True},
                )

            lab = cid == LAB or pending.get("lab")
            targets = {"lab": True} if lab else {"url": url}
            if lab:
                P, prov = plan_with_provider(
                    goal,
                    {
                        "url": "http://127.0.0.1:0",
                        "https": "https://127.0.0.1:0",
                        "spec": "x",
                        "iac": "x",
                        "manifest": "x",
                        "plist": "x",
                        "code": "x",
                        "ai": "x",
                        "tcp": "tcp://127.0.0.1",
                    },
                    True,
                    cfg,
                    det,
                )
            else:
                P, prov = plan_with_provider(goal, targets, False, cfg, det)
            explanation = Provider().explain(P) if det else prov.explain(P)
            active = [t for t in P["tasks"] if t.get("active") and t.get("target") and not is_lab(t["target"])]
            note = (
                f"\n⚠️ {len(active)} tarefa(s) ativa(s) vão pedir sua aprovação antes de rodar."
                if active
                else ""
            )
            jid = self.worker.create(
                user, "hacker", cid, goal, url if not lab else None, None, plan=P, chat_id=th["id"]
            )
            scope_txt = ", ".join(pending.get("scope_hosts") or []) or ("lab" if lab else url)
            return (
                f"Escopo autorizado confirmado ({scope_txt}). Missão #{jid} criada (provedor: {prov.name}).\n"
                f"{explanation}{note}\n"
                "Acompanhe com «status». Quando terminar, o resumo aparece aqui.",
                {
                    "intent": "mission",
                    "job": jid,
                    "provider": prov.name,
                    "plan": {"modules": P["modules"], "skipped": P["skipped"]},
                    "confirmed_scope": True,
                    "commands": pending.get("commands") or [],
                },
            )
        except Exception as e:
            return f"Não consegui criar a missão: {e}", {"intent": "mission", "error": str(e)}

    def _control(self, user, th, text, intent):
        if intent == "help":
            return HELP, {"intent": intent}
        if intent == "status":
            jobs = [
                j
                for j in self.store.q(
                    "SELECT id,status,goal,client_id,progress FROM jobs ORDER BY id DESC LIMIT 12"
                )
                if self._vis(user, j["client_id"])
            ]
            reply = "Fila recente:\n" + (
                "\n".join(
                    f"#{j['id']} [{j['status']}] {j['goal'][:80]}"
                    + (f" · {j['progress']}" if j.get("progress") else "")
                    for j in jobs
                )
                or "nenhuma tarefa"
            )
            return reply, {"intent": intent, "jobs": [j["id"] for j in jobs]}
        if intent in ("pause", "cancel"):
            jid = CMD.extract_job_id(text)
            if not jid:
                return f"Informe o número da tarefa, ex.: {'pausar' if intent == 'pause' else 'cancelar'} #3", {
                    "intent": intent
                }
            try:
                st = self.worker.pause(user, jid) if intent == "pause" else self.worker.cancel(user, jid)
                return f"Tarefa #{jid}: {st}", {"intent": intent, "job": jid, "status": st}
            except Exception as e:
                return f"Não foi possível: {e}", {"intent": intent, "error": str(e)}
        if intent == "approve_hint":
            pend = [
                a
                for a in self.store.q(
                    "SELECT id,job_id,target,client_id FROM approvals WHERE status='pendente'"
                )
                if self._vis(user, a.get("client_id", ""))
            ]
            reply = (
                (
                    "Há aprovações pendentes: "
                    + ", ".join(f"#{a['id']} (tarefa {a['job_id']} → {a['target']})" for a in pend)
                    + ". Abra Aprovações no menu para decidir com justificativa."
                )
                if pend
                else "Nenhuma aprovação pendente."
            )
            return reply, {"intent": intent, "approvals": [a["id"] for a in pend]}
        if intent == "explain":
            jid = CMD.extract_job_id(text)
            if not jid:
                return "Informe a tarefa, ex.: explica #3", {"intent": intent}
            j = self.store.q("SELECT * FROM jobs WHERE id=?", (jid,), one=True)
            if not j or not self._vis(user, j["client_id"]):
                return "Tarefa não encontrada", {"intent": intent}
            summ = json.loads(j["summary"] or "{}")
            plan = json.loads(j["plan_json"] or "{}") or {"modules": summ.get("modules", [])}
            prov = get_provider(self.cfg(), deterministic=self.deterministic())
            reply = prov.explain(
                plan
                if plan.get("modules")
                else {"modules": summ.get("modules", []), "tasks": [], "skipped": summ.get("skipped", [])},
                summ,
            )
            return reply, {"intent": intent, "job": jid, "provider": prov.name}
        if intent == "confirm":
            return (
                "Não há pedido pendente neste chat. Mande um comando (ex.: «verificar TLS do laboratório») e depois confirme o escopo.",
                {"intent": "confirm", "no_pending": True},
            )
        if intent == "abort_pending":
            return "Nenhum pedido pendente para cancelar.", {"intent": "abort_pending"}
        return HELP, {"intent": "help"}
