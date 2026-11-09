"""Chat de comandos do CyberSwarm Control.
Ordem em português → allow-list → prévia alvo/ação → confirmação ligada ao pedido → fila → resultado.
Sem shell livre, sem roubo de credencial, sem alvo fora do escopo autorizado.
Com provedor «none»: assistente de comandos determinístico (não é LLM conversacional)."""
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

    def provider_label(self):
        cfg = self.cfg()
        if self.deterministic() or (cfg.get("mode") or "none") == "none":
            return "assistente de comandos (regras fixas, sem LLM)"
        p = get_provider(cfg, deterministic=False)
        if p.name == "none":
            return "assistente de comandos (regras fixas, sem LLM)"
        return f"provedor {p.name}"

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

    def _clear_stale_pending(self, tid, reason=None):
        if self._pending_get(tid):
            self._pending_set(tid, None)
            return reason or "Pedido pendente anterior foi descartado (não vale para esta mensagem)."
        return None

    def post_job_result(self, jid):
        """Chamado pelo worker ao concluir/errar: empilha resumo útil no chat (sem inventar achados)."""
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
            lines = [f"Resultado da tarefa #{jid}: concluída."]
            mods = summ.get("modules") or []
            if mods:
                lines.append(f"Módulos: {', '.join(mods) if isinstance(mods, list) else mods}")
            elapsed = summ.get("elapsed_s")
            if elapsed is not None:
                lines.append(f"Tempo: {elapsed}s")
            # Tenta listar achados reais do banco do job (sem fabricar)
            findings = self._job_findings_brief(j)
            if findings:
                lines.append(f"Achados observados ({len(findings)}):")
                for f in findings[:8]:
                    sev = f.get("severity") or "?"
                    title = f.get("title") or f.get("check_id") or "?"
                    ev = (f.get("evidence") or "")[:160]
                    rec = (f.get("recommendation") or "")[:120]
                    lines.append(f"• [{sev}] {title}")
                    if ev:
                        lines.append(f"  evidência: {ev}")
                    if rec:
                        lines.append(f"  correção: {rec}")
                if len(findings) > 8:
                    lines.append(f"… e mais {len(findings) - 8}. Abra Achados/Relatório para o restante.")
            else:
                n = summ.get("findings") or summ.get("confirmed") or 0
                lines.append(f"Resumo numérico: achados={n}. Abra Achados para detalhes.")
            lines.append("Nada inventado — só o que a fila e os módulos registraram.")
            reply = "\n".join(lines)
        elif status == "erro":
            reply = f"Tarefa #{jid} falhou: {(j.get('error') or 'erro')[:400]}"
        else:
            reply = f"Tarefa #{jid} terminou com status «{status}»."
        meta = {"intent": "job_result", "job": jid, "status": status}
        self._add(tid, "assistant", reply, meta)
        self.audit.log("chat_job_result", thread=tid, job=jid, status=status)

    def _job_findings_brief(self, j):
        """Lê achados reais do cyberswarm.db do job — nunca inventa."""
        out = []
        try:
            import os, sqlite3
            from .worker import job_dir
            data = getattr(self.worker, "data", None)
            if not data:
                return out
            dbp = os.path.join(job_dir(data, j["client_id"], j["id"]), "cyberswarm.db")
            if not os.path.isfile(dbp):
                return out
            con = sqlite3.connect(dbp)
            con.row_factory = sqlite3.Row
            # schema pode variar levemente entre versões
            cols = {r[1] for r in con.execute("PRAGMA table_info(findings)").fetchall()}
            want = [c for c in ("check_id", "title", "severity", "evidence", "recommendation") if c in cols]
            if not want:
                con.close()
                return out
            rows = con.execute(
                f"SELECT {', '.join(want)} FROM findings ORDER BY id LIMIT 12"
            ).fetchall()
            con.close()
            return [dict(r) for r in rows]
        except Exception:
            return out

    def handle(self, user, tid, text):
        msgs, th = self.messages(user, tid)
        text = (text or "").strip()[:2000]
        if not text:
            raise ValueError("mensagem vazia")
        self._add(tid, "user", text)

        pending = self._pending_get(tid)
        ctrl = CMD.detect_control_intent(text)

        # 1) abort / confirm — confirm SÓ do pending atual (fingerprint)
        if pending and ctrl == "abort_pending":
            self._pending_set(tid, None)
            reply, meta = "Pedido cancelado. Nada foi executado.", {"intent": "abort_pending"}
            self._add(tid, "assistant", reply, meta)
            self.audit.log("chat_message", thread=tid, by=user["username"], intent="abort_pending", client=th["client_id"])
            return {"reply": reply, "meta": meta}

        if pending and ctrl == "confirm":
            # Confirmação só vale se o fingerprint ainda bate (alvo+ação deste pedido)
            fp = pending.get("fp") or CMD.pending_fingerprint(pending)
            if fp != CMD.pending_fingerprint(pending):
                self._pending_set(tid, None)
                reply, meta = (
                    "O pedido pendente estava inconsistente e foi descartado. Mande o comando de novo.",
                    {"intent": "confirm", "stale": True},
                )
            else:
                reply, meta = self._launch(user, th, pending, confirmed=True, expected_fp=fp)
                self._pending_set(tid, None)
            self._add(tid, "assistant", reply, meta)
            self.audit.log("chat_message", thread=tid, by=user["username"], intent=meta.get("intent"), client=th["client_id"])
            return {"reply": reply, "meta": meta}

        # 2) parser allow-list
        parsed = CMD.parse_command(text, th["client_id"], LAB)

        # Saudações / vague / refuse: descartam pending antigo (não autorizam lançamento depois)
        if parsed["action"] in ("greet", "clarify", "refuse", "none"):
            cleared = self._clear_stale_pending(tid)
            if parsed["action"] == "greet":
                reply = parsed.get("reply") or CMD.GREET_MSG
                if cleared:
                    reply += "\n\n(Descartei um pedido pendente anterior — ele não vale mais.)"
                meta = {"intent": "greet", "cleared_pending": bool(cleared)}
            elif parsed["action"] == "clarify":
                reply = parsed.get("reply") or CMD.CLARIFY_MSG
                if cleared:
                    reply = "(Pedido pendente anterior descartado.)\n\n" + reply
                meta = {"intent": parsed.get("intent") or "vague", "cleared_pending": bool(cleared)}
            elif parsed["action"] == "refuse":
                reply = parsed["error"]
                meta = {"intent": parsed.get("intent") or "refuse", "cleared_pending": bool(cleared)}
            else:
                reply = parsed.get("error") or CMD.CLARIFY_MSG
                meta = {"intent": "unknown", "cleared_pending": bool(cleared)}
            self._add(tid, "assistant", reply, meta)
            self.audit.log("chat_message", thread=tid, by=user["username"], intent=meta.get("intent"), client=th["client_id"])
            return {"reply": reply, "meta": meta}

        if parsed["action"] == "control":
            # status/help etc. não lançam; pending permanece só se for status/help/explain
            if parsed["intent"] in ("help", "status", "explain", "approve_hint", "pause", "cancel"):
                reply, meta = self._control(user, th, text, parsed["intent"])
            else:
                reply, meta = self._control(user, th, text, parsed["intent"])
            self._add(tid, "assistant", reply, meta)
            self.audit.log("chat_message", thread=tid, by=user["username"], intent=meta.get("intent"), client=th["client_id"])
            return {"reply": reply, "meta": meta}

        # propose: nova prévia substitui qualquer pending antigo (escopo velho NÃO autoriza ação nova)
        ok, err = self._validate_scope(th, parsed)
        if not ok:
            self._clear_stale_pending(tid)
            reply, meta = err, {"intent": "out_of_scope"}
        elif parsed.get("inline_confirm"):
            # inline: monta pending, lança na hora com o mesmo fp
            pending_body = self._pending_body(parsed)
            reply, meta = self._launch(user, th, pending_body, confirmed=True, expected_fp=pending_body["fp"])
            self._pending_set(tid, None)
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

    def _pending_body(self, parsed):
        pending = {
            "kind": parsed["kind"],
            "goal": parsed["goal"],
            "commands": list(parsed.get("commands") or []),
            "modules": list(parsed.get("modules") or []),
            "lab": bool(parsed.get("lab")),
            "lab_name": parsed.get("lab_name"),
            "target_url": parsed.get("target_url"),
            "target_label": parsed.get("target_label"),
            "scope_hosts": list(parsed.get("scope_hosts") or []),
            "created": time.time(),
        }
        pending["fp"] = CMD.pending_fingerprint(pending)
        return pending

    def _validate_scope(self, th, parsed):
        cid = th["client_id"]
        if parsed.get("kind") == "extval" or parsed.get("lab") or cid == LAB:
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
        pending = self._pending_body(parsed)
        self._pending_set(tid, pending)
        cmds = ", ".join(pending["commands"]) or "missão"
        desc = []
        for n in pending["commands"]:
            spec = CMD.ALLOWLIST.get(n) or {}
            if spec.get("desc"):
                desc.append(spec["desc"])
        action_txt = "; ".join(desc) or cmds
        hosts = ", ".join(pending["scope_hosts"]) or "(lab)"
        reply = (
            f"Prévia (ainda NÃO rodei nada):\n"
            f"• Ação: {action_txt}\n"
            f"• Alvo: {pending['target_label']}\n"
            f"• Hosts do escopo: {hosts}\n"
            f"• Objetivo interno: {pending['goal'][:240]}\n"
            f"• Modo: {self.provider_label()}\n"
            f"• Id do pedido: {pending['fp']}\n\n"
            "Para executar ESTE pedido, responda «escopo autorizado» (ou «confirmo»).\n"
            "Para desistir: «desistir». Um «oi» ou pedido vago descarta esta prévia."
        )
        meta = {
            "intent": "confirm_scope",
            "pending": True,
            "fp": pending["fp"],
            "commands": pending["commands"],
            "scope_hosts": pending["scope_hosts"],
            "target": pending["target_label"],
            "action": action_txt,
        }
        return reply, meta

    def _launch(self, user, th, pending, confirmed=False, expected_fp=None):
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
        fp_now = CMD.pending_fingerprint(pending)
        if expected_fp and expected_fp != fp_now:
            return "Confirmação não corresponde ao pedido pendente. Mande o comando de novo.", {
                "intent": "confirm",
                "stale": True,
            }
        if not pending.get("commands") and pending.get("kind") != "extval":
            return "Pedido sem ação definida — nada enfileirado.", {"intent": "confirm", "empty": True}

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
                    f"Confirmado (pedido {fp_now}). Validação externa #{jid} enfileirada "
                    f"({lab_name or 'juice-shop'}).\nModo: {self.provider_label()}. "
                    "Acompanhe com «status».",
                    {"intent": "mission", "job": jid, "lab": lab_name, "confirmed_scope": True, "fp": fp_now},
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
            # Explicação sempre pela regra (honesta); não finge LLM
            explanation = Provider().explain(P)
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
            label = self.provider_label()
            return (
                f"Confirmado (pedido {fp_now}, escopo {scope_txt}). Tarefa #{jid} enfileirada.\n"
                f"Modo: {label}.\n{explanation}{note}\n"
                "Acompanhe com «status». Quando terminar, o resumo com evidências aparece aqui.",
                {
                    "intent": "mission",
                    "job": jid,
                    "provider": "none" if (prov.name == "none" or det) else prov.name,
                    "provider_label": label,
                    "plan": {"modules": P["modules"], "skipped": P["skipped"]},
                    "confirmed_scope": True,
                    "commands": pending.get("commands") or [],
                    "fp": fp_now,
                },
            )
        except Exception as e:
            return f"Não consegui criar a missão: {e}", {"intent": "mission", "error": str(e)}

    def _control(self, user, th, text, intent):
        if intent == "help":
            return HELP + f"\n\nModo atual: {self.provider_label()}.", {"intent": intent}
        if intent == "status":
            jobs = [
                j
                for j in self.store.q(
                    "SELECT id,status,goal,client_id,progress,created,finished FROM jobs ORDER BY id DESC LIMIT 12"
                )
                if self._vis(user, j["client_id"])
            ]
            if not jobs:
                reply = "Fila: nenhuma tarefa registrada neste painel."
            else:
                lines = ["Fila recente (dados reais do banco):"]
                for j in jobs:
                    prog = f" · {j['progress']}" if j.get("progress") else ""
                    lines.append(f"#{j['id']} [{j['status']}] {(j.get('goal') or '')[:80]}{prog}")
                reply = "\n".join(lines)
            return reply, {"intent": intent, "jobs": [j["id"] for j in jobs], "count": len(jobs)}
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
            reply = Provider().explain(
                plan
                if plan.get("modules")
                else {"modules": summ.get("modules", []), "tasks": [], "skipped": summ.get("skipped", [])},
                summ,
            )
            brief = self._job_findings_brief(j)
            if brief:
                reply += "\n\nAchados (amostra real):\n" + "\n".join(
                    f"• [{f.get('severity')}] {f.get('title')}: {(f.get('evidence') or '')[:120]}" for f in brief[:5]
                )
            return reply, {"intent": intent, "job": jid, "provider": "none"}
        if intent == "confirm":
            return (
                "Não há pedido pendente neste chat. Mande um comando claro "
                "(ex.: «verificar cabeçalhos do laboratório») e depois confirme.",
                {"intent": "confirm", "no_pending": True},
            )
        if intent == "abort_pending":
            return "Nenhum pedido pendente para cancelar.", {"intent": "abort_pending"}
        return HELP, {"intent": "help"}
