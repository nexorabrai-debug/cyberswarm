"""Parser de comandos de chat: lista fixa (allow-list) → tipo de job / módulos.
NÃO executa shell, NÃO rouba credenciais, NÃO age fora do escopo.
Só mapeia texto em português para ações defensivas já existentes no CyberSwarm."""
from __future__ import annotations
import re
from urllib.parse import urlparse

# Ações permitidas no chat → (kind, modules|lab_hint, descrição curta)
# kind: hacker | extval | control (status/pause/etc tratados em chat.py)
ALLOWLIST = {
    "scan_web": {
        "kind": "hacker",
        "modules": ["web"],
        "desc": "checar cabeçalhos e superfície web",
        "rx": r"\b(cabe[cç]alh\w*|headers?|site|web|http)\b",
    },
    "scan_tls": {
        "kind": "hacker",
        "modules": ["tls"],
        "desc": "checar TLS/SSL e certificado",
        "rx": r"\b(tls|ssl|https|certificad\w*)\b",
    },
    "scan_api": {
        "kind": "hacker",
        "modules": ["api"],
        "desc": "revisar especificação/API",
        "rx": r"\b(apis?|openapi|swagger)\b",
    },
    "scan_network": {
        "kind": "hacker",
        "modules": ["network"],
        "desc": "varrer hosts/portas do laboratório (só 127.0.0.1)",
        "rx": r"\b(rede|network|portas?|ports?|hosts?|varredura|escane\w*|scan)\b",
    },
    "analyze_apk": {
        "kind": "hacker",
        "modules": ["android"],
        "desc": "analisar manifesto/APK Android no escopo",
        "rx": r"\b(apk|android|manifesto|mobile)\b",
    },
    "analyze_ios": {
        "kind": "hacker",
        "modules": ["ios"],
        "desc": "analisar plist iOS no escopo",
        "rx": r"\b(ios|iphone|ipad|plist)\b",
    },
    "analyze_code": {
        "kind": "hacker",
        "modules": ["codesec", "secrets"],
        "desc": "análise estática de código / segredos no caminho autorizado",
        "rx": r"\b(c[oó]digo|code|sast|fonte|segredos?|secrets?)\b",
    },
    "analyze_cloud": {
        "kind": "hacker",
        "modules": ["cloud"],
        "desc": "revisar IaC / cloud no escopo",
        "rx": r"\b(cloud|nuvem|terraform|iac)\b",
    },
    "analyze_ai": {
        "kind": "hacker",
        "modules": ["aisec"],
        "desc": "revisar prompts/IA no escopo",
        "rx": r"\b(ia|ai|llm|prompts?)\b",
    },
    "full_audit": {
        "kind": "hacker",
        "modules": None,  # planner escolhe pelo texto "completo"
        "desc": "auditoria defensiva completa (módulos do plano)",
        "rx": r"\b(complet[oa]|full|tud[oa]|auditoria|auditar|miss[aã]o)\b",
    },
    "extval": {
        "kind": "extval",
        "modules": None,
        "desc": "validação externa em laboratório registrado",
        "rx": r"\b(valida(r|ção)\s+externa|extval|juice|vampi|dvga|webgoat|insecurebank)\b",
    },
}

# Pedidos que o chat RECUSA de propósito (não estão na allow-list)
FORBIDDEN = [
    (r"\b(senha\s+do\s+wi-?fi|wi-?fi.{0,40}senha|senha.{0,40}wi-?fi|password.{0,40}wi-?fi|wi-?fi.{0,40}password)\b",
     "Não descubro nem testo senha de Wi-Fi/roteador. Isso seria roubo de credencial. Use só ações da lista (ex.: varrer portas de um host seu no escopo)."),
    (r"\b(crack(ear)?|quebr(ar|e)|roub(ar|e)|exfiltr\w*|keylog\w*|clipboard\s*monitor|persist[eê]ncia\s+malicios|backdoor|ransomware)\b",
     "Ação ofensiva/maliciosa fora do escopo defensivo. Só rodo checagens allow-listed em alvos seus/autorizados."),
    (r"\b(shell|terminal|bash|cmd\.exe|powershell|executar comando)\b",
     "Não há shell nem comando livre pelo chat. Só ações da allow-list viram tarefas do CyberSwarm."),
    (r"\b(banco real|pix real|conta corrente|cart[aã]o de cr[eé]dito)\b",
     "Não mexo em banco/Pix/cartão reais. Só laboratório ou escopo autorizado cadastrado."),
]

CONTROL_INTENTS = [
    (r"\b(status|andamento|progresso|fila)\b", "status"),
    (r"\b(paus(ar|e)|pause)\b", "pause"),
    (r"\b(cancel(ar|e)|parar|stop)\b", "cancel"),
    (r"\b(aprova|approve)\b", "approve_hint"),
    (r"\b(explica|resumo|o que (achou|encontrou)|resultado)\b", "explain"),
    (r"\b(ajuda|help|o que (você|voce) (faz|pode)|comandos?)\b", "help"),
    (r"\b(escopo\s+autorizado|autorizo\s+o\s+escopo|confirmo|confirm(ar|e)|pode\s+(rodar|executar)|ok,\s*pode)\b", "confirm"),
    (r"\b(desistir|cancela\s+pedido|n[aã]o\s+confirma|abortar)\b", "abort_pending"),
]

CONFIRM_INLINE = re.compile(
    r"\b(escopo\s+autorizado|autorizo\s+o\s+escopo|confirmo|confirm(ar|e))\b", re.I
)

LAB_HINT = re.compile(r"\b(laborat[oó]rio|lab|127\.0\.0\.1|localhost|local)\b", re.I)
URL_RE = re.compile(r"https?://[^\s\"'<>]+")
HOST_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b")
JOB_ID_RE = re.compile(r"#?\b(\d{1,8})\b")
EXTVAL_LABS = ("juice-shop", "webgoat", "vampi", "dvga", "insecurebankv2")


def help_text():
    lines = [
        "Sou o modo de conversa do CyberSwarm (Hacker AI). Você dá a ordem em português; eu mapeio para uma ação da lista e só executo depois de você confirmar o escopo.",
        "",
        "Comandos que entendo (allow-list):",
    ]
    for name, spec in ALLOWLIST.items():
        lines.append(f"• {name}: {spec['desc']}")
    lines += [
        "",
        "Controle: status | pausar #ID | cancelar #ID | explica #ID | ajuda",
        "Confirmação: responda «escopo autorizado» (ou «confirmo») depois que eu mostrar o alvo.",
        "",
        "Regras: só alvos seus/autorizados (campo escopo obrigatório); sem shell livre; sem roubo de senha/Wi-Fi; laboratório = 127.0.0.1.",
    ]
    return "\n".join(lines)


def detect_forbidden(text: str):
    t = (text or "").strip().lower()
    for rx, msg in FORBIDDEN:
        if re.search(rx, t, re.I | re.S):
            return msg
    return None


def detect_control_intent(text: str):
    t = (text or "").strip().lower()
    for rx, name in CONTROL_INTENTS:
        if re.search(rx, t):
            return name
    return None


def extract_url(text: str):
    m = URL_RE.search(text or "")
    return m.group(0).rstrip(".,;)") if m else None


def extract_host(text: str):
    m = HOST_RE.search(text or "")
    return m.group(0) if m else None


def extract_job_id(text: str):
    m = JOB_ID_RE.search(text or "")
    return int(m.group(1)) if m else None


def pick_extval_lab(text: str):
    t = (text or "").lower()
    for n in EXTVAL_LABS:
        if n.replace("-", " ") in t or n in t:
            return n
    return "juice-shop"


def match_commands(text: str):
    """Retorna lista ordenada de nomes ALLOWLIST que bateram no texto."""
    t = (text or "").lower()
    hits = []
    for name, spec in ALLOWLIST.items():
        if re.search(spec["rx"], t):
            hits.append(name)
    return hits


def build_goal(command_names, original_text: str) -> str:
    mods = []
    for n in command_names:
        spec = ALLOWLIST[n]
        if spec["modules"]:
            for m in spec["modules"]:
                if m not in mods:
                    mods.append(m)
    if not mods and "full_audit" in command_names:
        return f"auditoria completa: {original_text.strip()[:400]}"
    if not mods and "extval" in command_names:
        return original_text.strip()[:500]
    if mods:
        # força módulos via texto reconhecido pelo planner
        label = ", ".join(mods)
        return f"rodar módulos {label}: {original_text.strip()[:350]}"
    return original_text.strip()[:500]


def parse_command(text: str, client_id: str, lab_id: str = "_lab"):
    """Interpreta a mensagem. Retorna dict com action/error/pending fields.
    action: refuse | control | propose | none
    """
    text = (text or "").strip()
    if not text:
        return {"action": "refuse", "error": "mensagem vazia"}

    forbidden = detect_forbidden(text)
    if forbidden:
        return {"action": "refuse", "error": forbidden, "intent": "forbidden"}

    ctrl = detect_control_intent(text)
    # confirm/abort têm prioridade só quando não são a única palavra misturada com comando novo —
    # o chat decide se há pending.
    if ctrl in ("status", "pause", "cancel", "approve_hint", "explain", "help", "confirm", "abort_pending"):
        # se for confirm/abort, devolve control; se for help etc também
        # mas se for mission-like com confirm inline, tratamos abaixo
        if ctrl not in ("confirm", "abort_pending") or not match_commands(text):
            return {"action": "control", "intent": ctrl}

    hits = match_commands(text)
    url = extract_url(text)
    host = extract_host(text)
    lab = client_id == lab_id or bool(LAB_HINT.search(text))

    if not hits:
        # missão genérica defensiva (planner) — ainda precisa de escopo
        hits = ["full_audit"] if re.search(r"\b(verific\w*|chec\w*|test\w*|analis\w*|auditar|miss[aã]o)\b", text.lower()) else []
    if not hits:
        return {
            "action": "none",
            "intent": "unknown",
            "error": "Não entendi o comando. Digite «ajuda» para ver a allow-list.",
        }

    kind = "extval" if "extval" in hits else "hacker"
    lab_name = pick_extval_lab(text) if kind == "extval" else None
    modules = []
    for n in hits:
        ms = ALLOWLIST[n].get("modules") or []
        for m in ms:
            if m not in modules:
                modules.append(m)

    # alvo / escopo proposto
    if kind == "extval":
        target_label = f"lab extval:{lab_name}"
        target_url = None
        scope_hosts = ["127.0.0.1", "localhost"]
    elif lab or client_id == lab_id:
        target_label = "laboratório local (127.0.0.1)"
        target_url = None
        scope_hosts = ["127.0.0.1", "localhost"]
        if host and host not in ("127.0.0.1", "0.0.0.0"):
            # network fora de loopback no lab thread → recusar
            if host not in ("127.0.0.1",):
                return {
                    "action": "refuse",
                    "intent": "out_of_scope",
                    "error": f"Host {host} fora do laboratório. Cadastre o cliente com escopo autorizado ou use 127.0.0.1.",
                }
    else:
        if not url:
            return {
                "action": "refuse",
                "intent": "need_url",
                "error": "Fora do laboratório preciso da URL no escopo (ex.: https://www.seu-dominio.com.br) e do cliente autorizado.",
            }
        host_u = (urlparse(url).hostname or "").lower()
        target_label = url
        target_url = url
        scope_hosts = [host_u] if host_u else []

    # network fora do lab é bloqueado pelo planner; antecipar
    if "scan_network" in hits and not (lab or client_id == lab_id):
        return {
            "action": "refuse",
            "intent": "out_of_scope",
            "error": "Varredura de rede pelo chat só no laboratório (127.0.0.1).",
        }

    goal = build_goal(hits, text)
    inline_confirm = bool(CONFIRM_INLINE.search(text))
    return {
        "action": "propose",
        "intent": "command",
        "commands": hits,
        "kind": kind,
        "modules": modules,
        "goal": goal,
        "lab": lab or client_id == lab_id,
        "lab_name": lab_name,
        "target_url": target_url,
        "target_label": target_label,
        "scope_hosts": scope_hosts,
        "inline_confirm": inline_confirm,
    }
