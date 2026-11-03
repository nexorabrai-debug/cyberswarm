# Plano técnico — Hacker AI 1.0 (Etapa 1)

## Objetivo
Transformar o CyberSwarm em um sistema que **planeja, coordena especialistas, executa auditorias autorizadas, verifica, interpreta e mede a si mesmo**, sem LLM pago e sem sair do escopo. Não é um chatbot: o "cérebro" é determinístico (regras + memória), com gancho opcional para LLM local.

## Arquitetura

```
 objetivo (texto/YAML/JSON)
        │
   [Planejador] ──(LLM local opcional, desligado)──┐
        │  DAG de tarefas                            │
   [Portão de aprovação] ── nega/libera, audita ◄────┘
        │
   [Seletor de ferramentas] ◄── memória (desempenho por ferramenta)
        │
   [Orquestrador core 0.3 evoluído]  (paralelo por nível do DAG, retry, timeout, parcial)
        │  web · tls · api · cloud · android · ios · segredos · codesec · rede · IA
        │  └─► (hipótese) exploit-lab PoC (só 127.0.0.1)
   [Validador core] → [Verificação independente] → [Reavaliação de hipóteses]
        │
   [Threat Intel offline] → [Pesquisa de vulnerabilidades / cadeias]
        │
   [Memória operacional] · [Avaliador vs gabarito] · [Relatórios core]
   (todos falam pelo Barramento JSON — docs/INTERFACES.md)
```

## Etapas e entregas
| Etapa | Entrega | Prova |
|---|---|---|
| 0 | `docs/AUDITORIA_0.3.md` | documento |
| 1 | este plano + comparação de ferramentas | documento |
| 2 | `cyberswarm/hacker/` (planner, memory, selector, bus, approvals, verify, metrics, intel, engine, cli) | `tests/test_hacker.py` |
| 3 | 12 módulos (5 reaproveitados + 7 novos/novas camadas) | testes por módulo |
| 4 | ferramentas OSS instaladas via pip | `docs/FERRAMENTAS.md` |
| 5 | testes + CLI `cyberswarm hacker` | `pytest` |
| 6 | docs pt-BR, `docs/COMPARATIVO.md`, zip, PDF demo | arquivos |

## Os 12 módulos
| # | Especialidade | Implementação | Tipo |
|---|---|---|---|
| 1 | Web | `agents/web.py` (0.3) | reaproveitado |
| 2 | API | `agents/api.py` (0.3) | reaproveitado |
| 3 | Cloud | `agents/cloud.py` (0.3) + checkov como verificador | reaproveitado + ferramenta |
| 4 | Android | `agents/mobile.py` (0.3) | reaproveitado |
| 5 | iOS | `agents/ios.py` (0.3) | reaproveitado |
| 6 | Code Security | `agents/codesec.py`: semgrep (regras locais) / bandit / AST nativo | novo |
| 7 | Network | `agents/network.py`: TCP connect, nmap -sT se instalado; travado em 127.0.0.1 | novo |
| 8 | Threat Intelligence | `hacker/intel.py` + `hacker/data/threat_intel.json` (offline) | novo |
| 9 | Vulnerability Research | `hacker/intel.py::vuln_research` (notas CWE/ATT&CK + cadeias de ataque) | novo |
| 10 | Exploit Research (lab) | `agents/exploitlab.py`: PoC não-armada, reprodução 2× por hash, travada em 127.0.0.1 | novo |
| 11 | Security Validation | validador 0.3 + `hacker/verify.py` (re-execução + corroboração) | evoluído |
| 12 | AI Security | `agents/aisec.py` (prompts/config) + gancho garak desligado | novo |

## Comparação de ferramentas open source

Critérios pedidos: precisão, desempenho, custo, integração, manutenção, execução local. **Legenda:** ✅ medido aqui no laboratório em 03/11/2026; [não verificado] = conhecimento geral/documentação, não medido por nós. Nenhuma escolha foi feita por popularidade: a escolha final é por **disponibilidade + desempenho medido na memória operacional**.

| Ferramenta | Área | Precisão | Desempenho | Custo | Integração | Manutenção | Local | Decisão |
|---|---|---|---|---|---|---|---|---|
| **semgrep** 1.183.0 (CE) | SAST | ✅ lab: VP 8 / FP 0 / FN 0 com nossas 8 regras locais | ✅ 1,5–1,8 s (lab) | grátis (CE, LGPL-2.1) [licença não verificada] | JSON, `--metrics off`, regras locais (offline) | ativa [não verificado] | sim | **primária** p/ codesec |
| **bandit** 1.9.4 | SAST Python | ✅ lab: VP 7 / **FP 8** / FN 1 (alertas de import e subprocess seguro; não tem regra de DEBUG) | ✅ 0,13 s | grátis (Apache-2.0) | JSON simples | ativa (PyCQA) [não verificado] | sim | **verificador** (2ª opinião) |
| AST nativo | SAST Python | ✅ lab: VP 8 / FP 0 / FN 0 (8 regras, viés: escrito junto com o lab) | ✅ 0,01 s | grátis | nativo | nossa | sim | fallback |
| gitleaks | segredos | [não verificado] boa cobertura de padrões | [não verificado] rápido (Go) | grátis (MIT) | binário Go, **não instalável via pip** | ativa | sim | não instalado; detector nativo 0.3 mantido |
| trufflehog | segredos | [não verificado] verifica segredos **contra APIs reais** — desligar (seria tráfego a terceiros) | [não verificado] | grátis (AGPL) | binário Go | ativa | sim | não instalado |
| **sslyze** 6.3.1 | TLS | ✅ confirmou TLS 1.0/1.1 e ausência de HSTS no lab | ✅ 1,6 s | grátis (AGPL-3.0) | pip, JSON | ativa [não verificado] | sim | **verificador** TLS |
| testssl.sh | TLS | [não verificado] muito completo | [não verificado] lento (minutos) | grátis (GPL-2.0) | bash + openssl, não pip | ativa | sim | não instalado |
| nmap | rede | [não verificado] padrão da indústria | [não verificado] | grátis (NPSL) | binário/apt, **não pip** | ativa | sim | suportado se presente (`-sT`); **ausente nesta máquina** → fallback nativo |
| nuclei | web/CVE | [não verificado] depende de templates; alguns templates são ativos/intrusivos | [não verificado] rápido | grátis (MIT) | binário Go | ativa | sim | não integrado (exigiria curadoria de templates passivos) |
| OWASP ZAP | DAST web | [não verificado] scan ativo amplo | [não verificado] pesado (Java) | grátis (Apache-2.0) | API/daemon | ativa | sim | não integrado (ativo demais p/ escopo padrão) |
| MobSF | Android/iOS binário | [não verificado] análise de APK/IPA | [não verificado] pesado (Docker) | grátis (GPL-3.0) | API REST | ativa | sim | não integrado (lacuna conhecida) |
| **checkov** 3.4.3 | IaC | ✅ 26 checagens falharam no `main.tf` do lab; corroborou 7/7 achados cloud | ✅ 1,6 s (`--skip-download`) | grátis (Apache-2.0) | pip, JSON | ativa [não verificado] | sim | **verificador** cloud |
| tfsec | IaC | [não verificado] | [não verificado] | grátis | binário; projeto migrado p/ Trivy [não verificado] | em migração | sim | não usado |
| garak | IA (LLM red-team) | [não verificado] sondas de prompt injection contra **modelo em execução** | [não verificado] lento | grátis (Apache-2.0) | pip, precisa de modelo | ativa | sim (com modelo local) | **gancho desligado** (`CYBERSWARM_GARAK=1`), não testado |
| promptfoo | IA (avaliação) | [não verificado] | [não verificado] | grátis (MIT) | Node.js | ativa | sim | não integrado |
| Ollama | LLM local p/ planejador | n/a | [não verificado] | grátis | HTTP local | ativa | sim | **gancho desligado** (`CYBERSWARM_LLM=ollama`); ausente nesta máquina |

## Regras de segurança do 1.0
1. Teste ativo só em `127.0.0.1`/`localhost` ou em alvo registrado em `clients.json` **e** com token `active_client_test` válido em `approvals.json`.
2. `out_of_scope` é **sempre negado** (token não amplia escopo).
3. Alterar o sistema (instalar ferramentas) exige token `system_change`.
4. `network` e `exploitlab` são travados em 127.0.0.1 no próprio código, independentemente de escopo/aprovação.
5. Nenhum método HTTP de escrita; nenhuma carga ofensiva; segredos sempre mascarados.

## Orçamento de esforço (70/20/10)
Desenvolvimento/pesquisa ≈70% (camada hacker + 4 módulos + integrações), testes/validação ≈20% (25 testes novos + medições), integração/correções ≈10%. Nenhum serviço pago.
