# Ferramentas configuradas (Etapa 4)

Instaladas em 03/11/2026 com `pip`, num ambiente virtual próprio (`~/.cyberswarm-tools`, 615 MB) para não mexer no Python do sistema. O CyberSwarm procura ferramentas em: `$CYBERSWARM_TOOLBIN` → `~/.cyberswarm-tools/bin` → `PATH` (`cyberswarm/tools.py`).

| Ferramenta | Versão | Instalada? | Papel no Hacker AI | Testada |
|---|---|---|---|---|
| semgrep (CE) | 1.183.0 | ✅ | SAST primário (`codesec`), regras locais `cyberswarm/hacker/data/semgrep_rules.yml`, `--metrics off` | ✅ `test_codesec_external_tools[semgrep]` |
| bandit | 1.9.4 | ✅ | SAST alternativo + verificador de `codesec` | ✅ `test_codesec_external_tools[bandit]` |
| sslyze | 6.3.1 | ✅ | verificador independente TLS (TLS 1.0/1.1, HSTS) | ✅ demo (17 corroborações no total) |
| checkov | 3.4.3 | ✅ | verificador independente Terraform | ✅ demo |
| nmap | — | ❌ (não é pip; precisa `apt install nmap` = mudança de sistema) | rede (`-sT`) se presente | fallback nativo testado |
| gitleaks / trufflehog / nuclei / ZAP / MobSF / testssl.sh | — | ❌ (não pip ou pesado) | não integrados | — |
| garak | — | ❌ (desligado por padrão) | gancho IA opcional | — |
| Ollama | — | ❌ | gancho LLM local opcional do planejador | teste com mock |

## Como instalar
Com aprovação explícita (é alteração de sistema):
```
cp approvals.example.json approvals.json   # edite token/responsável/validade
cyberswarm hacker install-tools --approval APR-2026-0002-TROQUE-ESTE-VALOR
```
Sem token o comando é **negado** (código 3) e a negação vai para `reports/audit.log`.
Manual (equivalente): `python3 -m venv ~/.cyberswarm-tools && ~/.cyberswarm-tools/bin/pip install bandit semgrep sslyze checkov`.

Ver o que está disponível e o que o seletor escolheria: `cyberswarm hacker tools`.

## Sem as ferramentas
Tudo continua funcionando: `codesec` cai para o AST nativo, `network` para TCP connect nativo e a verificação para re-execução nativa. Testado com `CYBERSWARM_DISABLE_TOOLS=semgrep,bandit,nmap` e com um `bandit` quebrado de propósito (fallback registrado como `tool_fallback` na trilha).
