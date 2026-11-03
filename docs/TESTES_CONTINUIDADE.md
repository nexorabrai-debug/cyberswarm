# Testes de continuidade — CyberSwarm 2.0

Quando: 2026-11-03 (America/Sao_Paulo). Ambiente: box local.

Resultado: **14/14** checks OK.

| Check | Passou | Detalhe |
|---|---|---|
| `caught_executing` | sim | `{"status": "executando", "job": 1}` |
| `worker_resume_to_queue` | sim | `{"before": [{"id": 1, "status": "executando", "attempts": 1}], "after": [{"id": 1, "status": "na_fila", "attempts": 2}]}` |
| `no_duplicate_after_restart` | sim | `{"count": 1, "statuses": ["executando"]}` |
| `resume_completes` | sim | `{"status": "concluida", "findings": 32, "attempts": 3}` |
| `pause` | sim | `{"http": 200, "body": {"status": "pausada"}}` |
| `resume_paused` | sim | `{"http": 200, "body": {"status": "na_fila"}}` |
| `cancel` | sim | `{"http": 200, "body": {"status": "cancelada"}}` |
| `chat_creates_job` | sim | `{"job": 4, "intent": "mission", "provider": "none"}` |
| `chat_history_persisted` | sim | `{"n": 2, "keys": ["thread", "messages"]}` |
| `no_ai_blocks_complex` | sim | `{"why": "operação complexa sem plano pré-aprovado"}` |
| `no_ai_allows_passive` | sim | `{"n_passive": 5}` |
| `network_failure_visible` | sim | `{}` |
| `reconnect_after_outage` | sim | `{"login": 200}` |
| `dedupe_same_goal` | sim | `{"first": 5, "second": 5}` |

## Interpretação
- Jobs em `executando` são recolocados em `na_fila` na subida do Worker (sem segunda linha do mesmo objetivo).
- Pause/cancel/resume via API owner; chat cria job real e persiste mensagens.
- Modo determinístico (sem IA) bloqueia varredura ativa sem plano pré-aprovado.
- Após queda do servidor, cliente falha; ao subir de novo, login e fila seguem no mesmo SQLite.
