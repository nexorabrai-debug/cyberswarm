# Benchmarks 2.0 — antes / depois (2026-11-03, Brasília)

Definições iguais à 1.1 (`VALIDACAO_EXTERNA.md`): **detectado** = item oficial com ≥1 achado *confirmado* mapeado.
Precisão estrita = achados mapeados / todos os achados. Falso positivo manual **não** medido item a item.

## Antes (Hacker AI 1.1, com nuclei onde aplicável)

| Lab | Itens | Detectados | Revocação | Precisão estrita | Não reproduzidos |
|---|---|---|---|---|---|
| Juice Shop | 116 | 2 | 1,7% | 16,7% | 0 |
| WebGoat | 25 | 0 | 0% | 0% | 1 |
| VAmPI | 9 | 2 | 22,2% | 12,8% | 0 |
| DVGA | 23 | 2 | 8,7% | 7,1% | 7 |
| InsecureBankv2 | 25 | 13 | 52% | 81,8% | 4 |

## Depois (2.0 — labauth + SCA; nuclei desligado nesta medição para isolar o ganho)

| Lab | Itens | Detectados | Revocação | Precisão estrita | Não reproduzidos | Delta |
|---|---|---|---|---|---|---|
| Juice Shop | 116 | **3** | **2,6%** | — | 0 | +1 (`knownVulnerableComponentChallenge` via SCA) |
| WebGoat | 25 | 0 | 0% | — | — | 0 — **bloqueio**: melhorias autenticadas exigem fluxo de lição; Java extra não instalável via apt |
| VAmPI | 9 | **4** | **44,4%** | 23,1% | 0 | +2 (`jwt_…weak_signing_key`, `broken_object_level_authorization`) |
| DVGA | 23 | **3** | **13,0%** | 27,3% | 0 | +1 (`batch_query_attack` confirmado, antes só nuclei não reproduzido) |
| InsecureBankv2 | 25 | 13 | 52% | 81,8% | 4 | 0 (sem mudança nesta etapa) |

## O que foi implementado
- Agente `labauth` (só 127.0.0.1): login seed VAmPI, JWT HS256 com chave `secret`, BOLA em `/users/v1/admin`, GraphQL array batching.
- `Net.request` aceita POST/PUT **apenas** em 127.0.0.1/localhost (documentado).
- Agente `sca` no Juice Shop (lockfile) → Vulnerable Library.
- Mapeamentos atualizados em `extval/data/mapping.json`.

## Falsos negativos relevantes (ainda abertos)
- Juice Shop: ~113 itens (XSS/SQLi autenticados, desafios de lógica).
- WebGoat: 25/25 — crawler autenticado por lição não implementado.
- VAmPI: SQLi, mass assignment, RegexDoS, rate-limit abuse (DoS não executamos de propósito).
- DVGA: SSRF, command injection, XSS armazenado — exigiriam mutações mais agressivas; ficam para autorização explícita de laboratório futuro.

## Honestidade
Não há cobertura “completa”. O ganho medido é **+4 itens oficiais** no total (JS+1, VAmPI+2, DVGA+1) com evidência confirmada.

## Rodada 2 (2026-11-03 ~21:20 Brasília) — detecção segura, só 127.0.0.1, nuclei desligado

Medido com `cyberswarm hacker validate --lab <lab> --mode 1.1 --no-nuclei`.

| Lab | Antes (rodada 1) | Depois | Itens novos |
|---|---|---|---|
| VAmPI | 4/9 (44,4%) | **8/9 (88,9%)**, prec. estrita 30,2% | mass_assignment, sqli_injection, unauthorized_password_change, user_and_password_enumeration (+ rate_limiting mapeado) |
| DVGA | 3/23 (13,0%) | **8/23 (34,8%)**, prec. estrita 50,0% | aliases, deep_recursion, discovering, fingerprinting, graphiql, field_suggestions, introspection |
| Juice Shop | 3/116 (2,6%) | **5/116 (4,3%)**, prec. estrita 19,6% | exposedMetrics, passwordHashLeak, directoryListing, errorHandling |
| WebGoat | 3/25 | não remedido (lab parado) | — |
| InsecureBankv2 | 13/25 | sem mudança | — |

Não reproduzidos: 0 em todos. Checks novos de log de acesso, documento em /ftp e score-board ainda não mapearam item oficial do Juice Shop nesta medição.
Precisão estrita baixa = muitos achados confirmados que não estão na lista oficial (não são falsos positivos comprovados, só não-listados).
