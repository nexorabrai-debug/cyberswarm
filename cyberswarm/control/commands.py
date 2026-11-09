"""Parser de comandos de chat: lista fixa (allow-list) → tipo de job / módulos.
NÃO executa shell, NÃO rouba credenciais, NÃO age fora do escopo.
Só mapeia texto em português para ações defensivas já existentes no CyberSwarm.
Não é um LLM: sem provedor, é um assistente de comandos determinístico."""
from __future__ import annotations
import hashlib, re
from urllib.parse import urlparse

# Ações permitidas no chat → (kind, modules|lab_hint, descrição curta)
ALLOWLIST = {
    "scan_web": {
        "kind": "hacker",
        "modules": ["web"],
        "desc": "checar cabeçalhos e superfície web",
        "rx": r"\b(cabe[cç]alh\w*|headers?|site|web|http)\b",
        "examples": "«verificar cabeçalhos do laboratório»",
    },
    "scan_tls": {
        "kind": "hacker",
        "modules": ["tls"],
        "desc": "checar TLS/SSL e certificado",
        "rx": r"\b(tls|ssl|https|certificad\w*)\b",
        "examples": "«checar TLS do laboratório»",
    },
    "scan_api": {
        "kind": "hacker",
        "modules": ["api"],
        "desc": "revisar especificação/API",
        "rx": r"\b(apis?|openapi|swagger)\b",
        "examples": "«revisar API do laboratório»",
    },
    "scan_network": {
        "kind": "hacker",
        "modules": ["network"],
        "desc": "varrer hosts/portas do laboratório (só 127.0.0.1)",
        "rx": r"\b(rede|network|portas?|ports?|hosts?|varredura|escane\w*)\b",
        "examples": "«varrer portas do lab»",
    },
    "analyze_apk": {
        "kind": "hacker",
        "modules": ["android"],
        "desc": "analisar manifesto/APK Android no escopo",
        "rx": r"\b(apk|android|manifesto|mobile)\b",
        "examples": "«analisar APK do laboratório»",
    },
    "analyze_ios": {
        "kind": "hacker",
        "modules": ["ios"],
        "desc": "analisar plist iOS no escopo",
        "rx": r"\b(ios|iphone|ipad|plist)\b",
        "examples": "«analisar plist iOS»",
    },
    "analyze_code": {
        "kind": "hacker",
        "modules": ["codesec", "secrets"],
        "desc": "análise estática de código / segredos no caminho autorizado",
        "rx": r"\b(sast|segredos?|secrets?|análise\s+estática|analise\s+estatica)\b",
        "examples": "«análise estática no laboratório»",
    },
    "analyze_cloud": {
        "kind": "hacker",
        "modules": ["cloud"],
        "desc": "revisar IaC / cloud no escopo",
        "rx": r"\b(cloud|nuvem|terraform|iac)\b",
        "examples": "«revisar terraform do laboratório»",
    },
    "analyze_ai": {
        "kind": "hacker",
        "modules": ["aisec"],
        "desc": "revisar prompts/IA no escopo",
        "rx": r"\b(prompt\s*injection|aisec|segurança\s+de\s+(ia|llm))\b",
        "examples": "«revisar prompts de IA do laboratório»",
    },
    "full_audit": {
        "kind": "hacker",
        "modules": None,
        "desc": "auditoria defensiva completa (vários módulos)",
        "rx": r"\b(auditoria\s+completa|auditar\s+(tudo|o\s+lab|laborat)|missão\s+completa|full\s*audit)\b",
        "examples": "«auditoria completa do laboratório»",
    },
    "extval": {
        "kind": "extval",
        "modules": None,
        "desc": "validação externa em laboratório registrado",
        "rx": r"\b(valida(r|ção)\s+externa|extval|juice\s*shop|vampi|dvga|webgoat|insecurebank)\b",
        "examples": "«validação externa juice shop»",
    },
}

# Pedidos que o chat RECUSA de propósito
FORBIDDEN = [
    (
        r"\b(wi-?fi|wifi|roteador|wlan)\b",
        "Não descubro nem testo senha de Wi-Fi/roteador. Neste celular o CyberSwarm só fala com 127.0.0.1 "
        "(ou hosts que você cadastrou com autorização). Não tem acesso à interface do roteador nem à rede Wi-Fi. "
        "Peça algo que eu faço de verdade, ex.: «verificar cabeçalhos do laboratório».",
    ),
    (
        r"\b(crack(ear)?|quebr(ar|e)|roub(ar|e)|exfiltr\w*|keylog\w*|clipboard\s*monitor|persist[eê]ncia\s+malicios|backdoor|ransomware)\b",
        "Ação ofensiva/maliciosa fora do escopo defensivo. Só rodo checagens allow-listed em alvos seus/autorizados.",
    ),
    (
        r"\b(shell|terminal|bash|cmd\.exe|powershell|executar comando)\b",
        "Não há shell nem comando livre pelo chat. Só ações da allow-list viram tarefas do CyberSwarm.",
    ),
    (
        r"\b(banco real|pix real|conta corrente|cart[aã]o de cr[eé]dito)\b",
        "Não mexo em banco/Pix/cartão reais. Só laboratório ou escopo autorizado cadastrado.",
    ),
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

# Saudações curtas — NUNCA viram missão
GREETING_RE = re.compile(
    r"^\s*(oi+|ol[aá]|oie|eai|e\s*a[ií]|fala|salve|hey|hi|hello|bom\s*dia|boa\s*tarde|boa\s*noite)"
    r"([\s,!.?]*|[\s,!.?]*(tudo\s*bem|td\s*bem|blz|beleza)?[\s,!.?]*)\s*$",
    re.I,
)

# Código colado (Python e afins) — NUNCA executar
CODE_PASTE_RE = re.compile(
    r"(?m)^\s*(import\s+\w+|from\s+\w+\s+import\s+|def\s+\w+\s*\(|class\s+\w+\s*[:\(]|if\s+__name__\s*==|#!/usr/bin/env\s+python|print\s*\()",
)

# Pedido vago: quer "teste" sem ação/alvo claros
VAGUE_RE = re.compile(
    r"^\s*(quero\s+(um\s+)?teste|faz\s+(um\s+)?teste|testa\s*(a[ií])?|me\s+testa|"
    r"roda\s+(um\s+)?teste|qualquer\s+coisa|s[oó]\s+testar|teste\s*geral|"
    r"faz\s+algo|me\s+ajuda|o\s+que\s+voc[eê]\s+faz\??)\s*[.!]?\s*$",
    re.I,
)

CLARIFY_MSG = (
    "Beleza — me diga o alvo e a ação. Exemplos que funcionam de verdade:\n"
    "• verificar cabeçalhos do laboratório\n"
    "• checar TLS do laboratório\n"
    "• varrer portas do lab\n"
    "• auditoria completa do laboratório\n\n"
    "Sou um assistente de comandos (regras fixas). Sem provedor de IA configurado, "
    "não invento missões a partir de papo solto. Digite «ajuda» para mais opções."
)

GREET_MSG = (
    "Oi! Sou o assistente de comandos do CyberSwarm — não um chatbot de IA livre. "
    "Diga o que quer auditar (ex.: «verificar cabeçalhos do laboratório»). "
    "Eu mostro alvo/ação e só rodo depois de você confirmar com «escopo autorizado»."
)


def help_text():
    lines = [
        "Assistente de comandos do CyberSwarm (não é LLM com provedor «none»).",
        "Você escreve a ordem em português → eu mostro alvo e ação → você confirma «escopo autorizado».",
        "",
        "O que eu sei fazer (só em laboratório 127.0.0.1 ou host autorizado):",
    ]
    for spec in ALLOWLIST.values():
        lines.append(f"• {spec['desc']} — ex.: {spec.get('examples', '')}")
    lines += [
        "",
        "Controle: status · pausar #ID · cancelar #ID · explica #ID · ajuda · desistir",
        "",
        "Limites honestos: sem senha de Wi-Fi; sem shell livre; sem executar código colado; "
        "sem banco/Pix real. Cabeçalhos ausentes saem com a gravidade da tabela (ex.: CSP=médio, XFO=baixo) — não invento «crítico».",
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
    t = (text or "").lower()
    hits = []
    for name, spec in ALLOWLIST.items():
        if re.search(spec["rx"], t):
            hits.append(name)
    return hits


def looks_like_code(text: str) -> bool:
    t = text or ""
    if CODE_PASTE_RE.search(t):
        return True
    # bloco multilinha típico de Python colado
    lines = [ln for ln in t.splitlines() if ln.strip()]
    if len(lines) >= 3:
        pyish = sum(
            1
            for ln in lines
            if re.match(r"^\s*(import |from |def |class |return |print\(|#if |# )", ln)
            or ln.rstrip().endswith(":")
            or re.match(r"^\s{4,}\S", ln)
        )
        if pyish >= 3:
            return True
    return False


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
        label = ", ".join(mods)
        return f"rodar módulos {label}: {original_text.strip()[:350]}"
    return original_text.strip()[:500]


def pending_fingerprint(pending: dict) -> str:
    """Assina alvo+ação do pedido pendente — confirmação só vale para este pedido."""
    parts = [
        pending.get("kind") or "",
        ",".join(pending.get("commands") or []),
        pending.get("target_label") or "",
        pending.get("target_url") or "",
        ",".join(pending.get("scope_hosts") or []),
        pending.get("goal") or "",
        pending.get("lab_name") or "",
    ]
    return hashlib.sha256("|".join(parts).encode()).hexdigest()[:24]


def parse_command(text: str, client_id: str, lab_id: str = "_lab"):
    """Interpreta a mensagem.
    action: refuse | control | propose | none | greet | clarify
    """
    text = (text or "").strip()
    if not text:
        return {"action": "refuse", "error": "mensagem vazia", "intent": "empty"}

    if GREETING_RE.match(text):
        return {"action": "greet", "intent": "greet", "reply": GREET_MSG}

    if looks_like_code(text):
        return {
            "action": "refuse",
            "intent": "code_paste",
            "error": (
                "Isso parece código colado. Eu não executo Python/shell pelo chat. "
                "Para análise estática, use um caminho autorizado no laboratório "
                "(ex.: «análise estática no laboratório»), não cole o programa aqui."
            ),
        }

    forbidden = detect_forbidden(text)
    if forbidden:
        return {"action": "refuse", "error": forbidden, "intent": "forbidden"}

    ctrl = detect_control_intent(text)
    if ctrl in ("status", "pause", "cancel", "approve_hint", "explain", "help", "confirm", "abort_pending"):
        if ctrl not in ("confirm", "abort_pending") or not match_commands(text):
            return {"action": "control", "intent": ctrl}

    hits = match_commands(text)
    url = extract_url(text)
    host = extract_host(text)
    lab = client_id == lab_id or bool(LAB_HINT.search(text))

    # Sem hit na allow-list: NÃO cair em full_audit genérico (bug 2.1.0: «Quero um teste»)
    if not hits:
        if VAGUE_RE.match(text) or len(text) <= 2:
            return {"action": "clarify", "intent": "vague", "reply": CLARIFY_MSG}
        # palavras soltas tipo "teste", "D", etc.
        return {"action": "clarify", "intent": "unknown", "reply": CLARIFY_MSG}

    kind = "extval" if "extval" in hits else "hacker"
    lab_name = pick_extval_lab(text) if kind == "extval" else None
    modules = []
    for n in hits:
        ms = ALLOWLIST[n].get("modules") or []
        for m in ms:
            if m not in modules:
                modules.append(m)

    if kind == "extval":
        target_label = f"lab extval:{lab_name}"
        target_url = None
        scope_hosts = ["127.0.0.1", "localhost"]
    elif lab or client_id == lab_id:
        target_label = "laboratório local (127.0.0.1)"
        target_url = None
        scope_hosts = ["127.0.0.1", "localhost"]
        if host and host not in ("127.0.0.1", "0.0.0.0", "localhost"):
            return {
                "action": "refuse",
                "intent": "out_of_scope",
                "error": f"Host {host} fora do laboratório. Cadastre o cliente com escopo autorizado ou use 127.0.0.1.",
            }
    else:
        if not url:
            return {
                "action": "clarify",
                "intent": "need_url",
                "reply": (
                    "Fora do laboratório preciso da URL no escopo do cliente autorizado "
                    "(ex.: https://www.seu-dominio.com.br). Cadastre o host antes."
                ),
            }
        host_u = (urlparse(url).hostname or "").lower()
        target_label = url
        target_url = url
        scope_hosts = [host_u] if host_u else []

    if "scan_network" in hits and not (lab or client_id == lab_id):
        return {
            "action": "refuse",
            "intent": "out_of_scope",
            "error": "Varredura de rede pelo chat só no laboratório (127.0.0.1).",
        }

    # Ação clara sem alvo implícito de lab/URL → pedir clarificação
    if not (lab or client_id == lab_id or target_url or kind == "extval"):
        return {"action": "clarify", "intent": "need_target", "reply": CLARIFY_MSG}

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
