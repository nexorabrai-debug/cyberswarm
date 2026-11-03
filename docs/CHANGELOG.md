# Changelog — CyberSwarm

## 2026-11-03 (sem cartão)

- Pesquisa free tiers sem cartão; top: Serv00, Render Free.
- `GET /api/ping`; env PORT/CONTROL_DATA/CONTROL_SECURE_COOKIE; Dockerfile single-process.
- `deploy/serv00/*`, `deploy/render/*`, `docs/IMPLANTACAO_SEM_CARTAO.md`.


## [2.0.1] — 2026-11-03 (Brasília)

### Adicionado
- Worker daemon independente (`cyberswarm worker`) — sobrevive ao fechar o navegador.
- Fila persistente v2 ligada ao Hacker AI e ao Control (checkpoint por tarefa, retomada após kill).
- Chat Hacker AI no Control (linguagem natural → plano → fila), com histórico por cliente.
- Camada de provedores de IA: none / ollama / OpenAI-compatível (chave só no servidor, criptografada).
- Modo determinístico sem IA (continua tarefas pré-aprovadas).
- HTTPS no Control (TLS autoassinado por padrão).
- Páginas de chat e configurações na PWA; UX A32 (~412px).
- Melhorias de cobertura (JWT, BOLA lab-only, GraphQL batching lab-only, semgrep/bandit).
- Documentação: MANUAL_A32, MANUAL_OPERACAO, LIMITACOES, CHECKLIST_SEGURANCA, IMPLANTACAO, BENCHMARKS_2.0.
- Testes de aceitação (`tests/acceptance/`).

### Alterado
- Control worker: dedupe de missões iguais, tentativas, pause/cancel, limites de recurso.
- Sessão: cookie Secure sob HTTPS, rotação no login, timeout configurável.

### Núcleo (aditivo)
- `agents/sca.py` (Etapa C), `agents/labauth.py` (JWT/BOLA/GraphQL lab).
- `v2/*` (fila, cache, determinístico, modelo, confiança, bench).
- `control/chat.py`, `control/daemon.py`, `control/tlsutil.py`, `providers.py`.

## 2026-11-03 — CyberSwarm 2.0 phone-control (etapas A–H)
- A: worker Control +  daemon; fila persistente, dedupe, pause/cancel, resume na_fila, persist_queue, limites.
- B: chat Hacker AI (parser pt-BR), providers none/ollama/openai-compat, settings sem eco de chave, histórico por cliente.
- C: UX mobile + screenshots /workspace/a32-{login,dashboard,chat,tasks,findings,approvals}.png @412×915 CSS.
- D: TLS self-signed (`--tls`), Secure cookie, checklist CHECKLIST_SEGURANCA.md.
- E: Dockerfile/compose/install.sh, IMPLANTACAO.md; cloudflared quick tunnel **bloqueado** neste box (porta 7844). OWNER_CREDENTIALS.txt (chmod 600) com senha local.
- F: APK não gerado (sem Java/SDK); PWA + Bubblewrap documentados.
- G: BENCHMARKS_2.0.md — Juice 3/116, WebGoat 0/25 (Java), VAmPI 4/9, DVGA 3/23, InsecureBank 13/25.
- H: tests/acceptance/ (14 critérios; 1b phone_required skip).
