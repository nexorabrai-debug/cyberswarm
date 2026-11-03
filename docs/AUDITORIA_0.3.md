# Auditoria honesta da arquitetura do CyberSwarm 0.3 (Etapa 0)

Data: 03/11/2026. Base: código em `cyberswarm/` v0.3.0 (≈990 linhas Python, 72 testes passando).

## O que funciona e foi REAPROVEITADO no Hacker AI 1.0

| Componente 0.3 | Arquivo | Por que reaproveitar | Como foi usado no 1.0 |
|---|---|---|---|
| Orquestrador asyncio (fila + workers + timeout por tarefa) | `orchestrator.py` | Simples, testado, paralelo | **Evoluído** (não reescrito): tentativas com backoff, `PartialResult`, gancho `on_task`, `finalize=False` para executar por nível do DAG |
| Controle de escopo deny-by-default | `scope.py` | Base de segurança do produto | Mantido; aceita esquema `tcp://` só para hosts do escopo |
| Net com rate limit, timeout, orçamento e só GET/HEAD/OPTIONS | `net.py` | Garante testes passivos | Mantido; cada verificação usa um `Net` novo (orçamento independente) |
| Trilha de auditoria com hash encadeado | `audit.py` | Prova de conduta | Mantida; registra plano, aprovações/negações, fallback de ferramentas, mudanças de sistema |
| Catálogo central de gravidade | `checks.py` | Uma fonte de verdade | +23 checagens (codesec, rede, IA, PoC, chaves de IA/Stripe) |
| Validador (fingerprint, confirmado/suspeita, teto de suspeita) | `agents/validation.py` | Regra de evidência já correta | Mantido; prova `tcp` adicionada |
| Agentes web, tls, api, cloud, mobile, ios, code | `agents/*.py` | Funcionam no lab, 0 FP medidos | Reutilizados como módulos 1–5 e "segredos" |
| Relatórios MD/HTML/PDF e comparação | `report.py` | PDF verificado | Evoluído: seções extras do Hacker AI (plano, ferramentas, verificação, hipóteses, cadeias, métricas) |
| SQLite de execuções/tarefas/achados | `db.py` | Histórico do core | Mantido; memória do Hacker AI fica em banco separado |

## Fraquezas encontradas (e o que o 1.0 fez)

| # | Fraqueza no 0.3 | Gravidade p/ produto | Tratamento no 1.0 |
|---|---|---|---|
| 1 | Sem planejamento: a lista de agentes é fixa no CLI | Alta | Planejador por regras → DAG (`hacker/planner.py`) |
| 2 | Sem memória entre execuções (só a tabela de findings por run) | Média | Memória operacional (`hacker/memory.py`) |
| 3 | Nenhuma ferramenta externa; só detectores próprios | Média | Seletor + integração bandit/semgrep/sslyze/checkov/nmap com fallback |
| 4 | "Confirmado" = prova bem formada, mas **não re-executada** | Alta | Verificação independente: re-execução + corroboração por 2ª ferramenta |
| 5 | Falha de agente = tarefa perdida (sem retry/parcial) | Média | Retries, `PartialResult`, timeout por tarefa |
| 6 | Sem medida de qualidade (precisão/revocação) | Alta | Gabarito do lab + avaliador (`hacker/metrics.py`) |
| 7 | Sem portão de aprovação para operações sensíveis (só escopo) | Alta | `hacker/approvals.py` + `approvals.json` |
| 8 | Comunicação entre agentes implícita (listas Python) | Média | Barramento com esquema JSON documentado (`docs/INTERFACES.md`) |
| 9 | Sem SAST de código (só segredos), sem rede, sem IA | Alta | Módulos `codesec`, `network`, `aisec` |
| 10 | Sem contexto de ameaça (CWE/ATT&CK/CVE) | Média | `hacker/intel.py` com base offline |
| 11 | Laboratório escrito pela mesma equipe que escreve os detectores (viés) | Alta | **Não resolvido**: métricas 1.0 medem regressão no lab, não acerto no mundo real (ver COMPARATIVO) |
| 12 | Mobile/iOS só leem manifest/plist, não binários | Média | Não resolvido (MobSF avaliado, não integrado) |
| 13 | Termux nunca testado em celular real | Baixa | Não resolvido |

## Decisão
Evoluir, não reescrever: a camada `cyberswarm/hacker/` fica **em cima** do core e conversa com ele só por interfaces (contrato de achado, `Agent`, `Orchestrator`, `write_reports`). Os comandos 0.3 (`scan`, `demo`, `demo-comercial`, `compare`...) continuam iguais e todos os 72 testes antigos continuam passando.
