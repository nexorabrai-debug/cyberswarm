# Comparativo CyberSwarm 0.3 × Hacker AI 1.0

Medido em 03/11/2026, mesma máquina, mesmo laboratório local (127.0.0.1), mesmo gabarito `cyberswarm/labdata/ground_truth.json` (83 itens plantados + negativos). Comandos: `cyberswarm demo` (0.3) e `cyberswarm hacker demo` (1.0), `cyberswarm hacker bench`.

| Métrica | 0.3 | 1.0 |
|---|---|---|
| Achados | 65 | 83 (82 confirmados, 1 suspeita) |
| Verdadeiros positivos / Falsos positivos / Falsos negativos | 65 / 0 / 18 | 83 / 0 / 0 |
| Precisão | 1,00 | 1,00 |
| Revocação | 0,78 | 1,00 |
| F1 | 0,88 | 1,00 |
| FN por área (0.3) | IA 5, código 8, PoC 3, rede 2 | — |
| Tempo da demo | ≈5,2 s | ≈7,9 s (9,0 s total) |
| Tarefas / níveis do DAG | 7 fixos | 17 em 7 níveis (planejados) |
| Verificação independente | não | 82/82 reproduzidos, 0 rebaixados, 17 corroborados por 2ª ferramenta (checkov, bandit, sslyze) |
| Hipóteses | não | 2 (1 confirmada por PoC no lab, 1 aberta) |
| Cadeias de ataque explicadas | não | 5 (só a partir de achados confirmados) |
| Memória entre execuções | não | sim: 2ª execução = 0 novos, 83 recorrentes |
| Mensagens no barramento | — | 203 |
| Ferramentas externas | 0 | 4 instaladas (semgrep, bandit, sslyze, checkov) |
| Checagens no catálogo | 52 | 75 |
| Testes automatizados | 72 | 97 (72 antigos + 25 novos), todos passando |

## Motores de código (mesmo lab, `cyberswarm hacker bench`)
| Motor | VP | FP | FN | Tempo |
|---|---|---|---|---|
| AST nativo | 8 | 0 | 0 | 0,01 s |
| bandit 1.9.4 | 7 | 8 | 1 | 0,13 s |
| semgrep 1.183.0 (regras locais) | 8 | 0 | 0 | 1,5 s |

## Leitura honesta
- **O ganho de revocação vem de cobertura nova** (código, rede, IA, PoC), não de detectores "mais inteligentes" nas áreas antigas.
- **Viés:** o laboratório e o gabarito foram escritos pela mesma equipe que escreveu os detectores. 100% aqui é **teste de regressão**, não promessa de acerto em cliente real. Precisa de benchmark externo (ex.: OWASP Benchmark, apps vulneráveis públicos rodando localmente) — não feito.
- A "verificação independente" só é realmente independente onde existe 2ª ferramenta (17 achados). Nos outros 65 é re-execução do mesmo código em contexto novo (pega instabilidade, não pega erro de lógica).
- O 1.0 é ≈50% mais lento por causa da verificação e das ferramentas externas (semgrep/sslyze/checkov ≈1,6 s cada).
