# Changelog — CyberSwarm

## [2.1.1] — 2026-11-09 (America/Sao_Paulo)

### Corrigido
- Saudações («Oi», «olá») e pedidos vagos («Quero um teste», «D») **não** criam missão nem pending.
- «Meu Wi-Fi» / qualquer menção a Wi-Fi explica o limite do aparelho (só 127.0.0.1 / hosts autorizados) — sem fingir crack.
- Código Python colado é recusado (sem shell/execução).
- Confirmação «escopo autorizado» fica ligada ao fingerprint do pedido (alvo+ação); saudação/vago descarta pending antigo.
- Label honesta: com provedor «none» = assistente de comandos (regras fixas, sem LLM).
- Removido fallback perigoso `test*` → `full_audit` da 2.1.0.

### Útil
- Prévia clara ação/alvo antes de enfileirar.
- Resumo no chat com achados reais (evidência + correção da tabela), sem inventar gravidade.

## [2.1.0] — 2026-11-09 (America/Sao_Paulo)

### Adicionado
- **Chat de comandos** no Control: você escreve a ordem em português e o painel mapeia para uma allow-list (web, TLS, API, rede lab, APK, código, auditoria…).
- Confirmação obrigatória «escopo autorizado» antes de enfileirar qualquer missão.
- Resumo da tarefa volta para o chat ao concluir (ou em erro).
- Recusa explícita de senha de Wi-Fi, shell livre, roubo de credencial e alvo fora do escopo.
- Testes em `tests/test_chat_commands.py` (+ ajustes de aceitação/control).

### Alterado
- Título do chat na PWA: «Chat de comandos».
- `control/chat.py` reescrito em cima de `control/commands.py`.
- Coluna `pending` em `chat_threads` para guardar a confirmação de escopo.

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
