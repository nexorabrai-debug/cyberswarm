# Interfaces do Hacker AI 1.0 (barramento de mensagens e contratos)

Todos os componentes (Planejador, Portão de aprovação, Seletor de ferramentas, Orquestrador/Core, Auditores Web/API/Cloud/Mobile/iOS/Code/CodeSec/Rede/IA/Exploit-lab, Verificador, Threat Intel, Pesquisa de vulnerabilidades, Avaliador e Relatórios) trocam tarefas e evidências por **mensagens JSON** no barramento `cyberswarm/hacker/bus.py`. Toda mensagem é validada (`validate_message`) e gravada na memória operacional (`hacker_memory.db`, tabela `messages`). O JSON completo do barramento de cada execução fica em `reports/hacker-<n>.json` (chave `bus`).

## Esquema da mensagem (JSON Schema 2020-12)

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "title": "CyberSwarm Hacker AI message",
  "type": "object",
  "required": ["id", "ts", "type", "sender", "recipient", "run_id", "payload"],
  "additionalProperties": false,
  "properties": {
    "id": {"type": "integer"},
    "ts": {"type": "number"},
    "type": {"enum": ["approval", "error", "finding", "hypothesis", "metric", "plan", "task", "task_result", "tool_selection", "verification"]},
    "sender": {"type": "string"},
    "recipient": {"type": "string", "description": "nome do agente ou '*'"},
    "run_id": {"type": ["integer", "null"]},
    "payload": {"type": "object"}
  }
}
```

Campos: `id` (sequencial por execução), `ts` (epoch), `type`, `sender`, `recipient`, `run_id` (execução do Hacker AI), `payload`.

## Payloads por tipo

| type | sender | payload |
|---|---|---|
| `plan` | planner | `modules[]`, `tasks` (int), `skipped[[módulo, motivo]]`, `levels[[ids]]` |
| `approval` | gate | `task`, `op` (`active_client_test`/`out_of_scope`/`system_change`), `target`, `granted` (bool) |
| `tool_selection` | selector | `module`, `tool`, `reason`, `ranking[{tool, available, score, why}]` |
| `task` | planner | `task`, `agent`, `target` (recipient = agente) |
| `task_result` | agente | `target`, `status` (`done`/`partial`/`error`/`rejected`), `findings`, `secs`, `attempts`, `tool` |
| `finding` | agente | `fingerprint`, `check_id`, `status`, `severity` |
| `verification` | verifier | `fingerprint`, `reproduced` (bool), `corroborated_by` (ferramenta ou null) |
| `hypothesis` | verifier | `id`, `fingerprint`, `status` (`aberta`/`confirmada`/`refutada`/`descartada`) |
| `metric` | evaluator | `tp`, `fp`, `fn`, `precision`, `recall`, `f1` |

## Contrato de achado (finding) — compartilhado com o Core 0.3

Gerado por `Agent.finding()` (`cyberswarm/registry.py`), enriquecido pelo validador e pelo Hacker AI:

`agent, check_id, title, severity, target, evidence, impact, recommendation, refs[], proof{type: http|tls|tcp|file, ...}, repro`
+ validador: `fingerprint, status (confirmado|suspeita), priority`
+ Hacker AI: `task_target, verification{reproduced, method, corroborated_by}, intel{cwe, attack, owasp_llm, cves}, research, memory (novo|recorrente)`.

`proof` reproduzível por tipo: `http` (`request`, `response`, `curl`), `tls`/`tcp` (`command`, `observed`), `file` (`path`, `line`, `line_sha`, `snippet` mascarado).

## Contrato de agente (módulo)

```python
@register
class MeuAuditor(Agent):
    name = "meu"; kind = "url" | "path"
    async def run(self, target) -> list[finding]   # pode lançar PartialResult(findings, motivo)
```
Lê `ctx.options["tools"][name]` (ferramenta escolhida) e grava `ctx.options["tool_used"][name]` (ferramenta realmente usada, após fallback).

## Arquivos de controle

- `clients.json` — escopo autorizado por cliente (v0.3, inalterado).
- `approvals.json` — tokens de aprovação: `{"approvals":[{"token","op","target","client_id","approved_by","expires":"AAAA-MM-DD"}]}`. Exemplo: `approvals.example.json`.
- `cyberswarm/labdata/ground_truth.json` — gabarito do laboratório: `{"items":[{"module","check_id","target","match","why"}], "negatives":[...]}`.
