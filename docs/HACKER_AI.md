# Hacker AI 1.0 — instalação e operação

Camada de planejamento e coordenação **defensiva** sobre o CyberSwarm. Não ataca terceiros, não testa nada fora do escopo, não usa serviço pago.

## Instalar
```
cd cyberswarm
python3 -m venv .venv && . .venv/bin/activate
pip install .                       # núcleo (só stdlib + fpdf2)
# opcional, com aprovação: ferramentas OSS (ver docs/FERRAMENTAS.md)
cyberswarm hacker install-tools --approval <token system_change>
```

## Operar
| Comando | O que faz |
|---|---|
| `cyberswarm hacker demo` | sobe o lab local, planeja, executa os 12 módulos, verifica, mede contra o gabarito e gera relatório + PDF |
| `cyberswarm hacker --goal "auditar laboratório completo"` | mesmo fluxo a partir de um objetivo em texto |
| `cyberswarm hacker plan --goal "revisar código e IA"` | só mostra o plano (DAG), não executa |
| `cyberswarm hacker --goal plano.yml` | objetivo em YAML/JSON (`goal`, `modules`, `skip`, `targets`) |
| `cyberswarm hacker --client acme --target https://acme.com.br --goal "web e tls" --approval APR-...` | cliente real: precisa estar em `clients.json` **e** ter token `active_client_test` em `approvals.json`; sem isso é negado e auditado |
| `cyberswarm hacker bench` | compara motores de código (nativo, bandit, semgrep) |
| `cyberswarm hacker memory` | resumo da memória operacional (execuções, hipóteses, desempenho de ferramentas) |
| `cyberswarm hacker tools` | ferramentas disponíveis e escolha do seletor |

Opções globais vêm antes do subcomando: `cyberswarm --out relatorios --no-pdf hacker demo`.
Forçar ferramenta: `--tool codesec=bandit`. LLM local opcional: `CYBERSWARM_LLM=ollama` (só pode **acrescentar** módulos conhecidos ao plano).

## Saídas
Em `--out` (padrão `reports/`): `report.md/.html/.pdf` com seções do Hacker AI, `findings.json`, `audit.log` (hash encadeado), `hacker_memory.db`.

## Memória operacional ≠ treinamento
`hacker_memory.db` guarda execuções, histórico de achados, hipóteses, desempenho de ferramentas e mensagens. Ela **não** treina nenhum modelo; só informa o seletor e a reavaliação de hipóteses. Pode ser apagada a qualquer momento.

## Aprovações (`approvals.json`)
Copie `approvals.example.json`. Cada token: `op` (`active_client_test` | `system_change`), `target`, `approved_by`, `expires`. `out_of_scope` nunca é aprovável.
