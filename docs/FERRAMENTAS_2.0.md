# Ferramentas avaliadas para o CyberSwarm 2.0 (Etapa C)

Regra de decisão: **integrar só o que adiciona cobertura medida e instala grátis**. "Cobertura medida" = detecta item de
ground truth (GT) que o núcleo não detectava, com prova reproduzível. Achado de ferramenta sozinho continua "suspeita".
Box usado: 8 vCPU, 15 GB RAM, sem Docker, sem apt, sem Java. Medições em 2026-11-03 (horário de Brasília, UTC-3).
Benchmarks (`cyberswarm.v2.bench`, os.wait4: parede / CPU / RAM máx.) estão em `/tmp/v2/bench.json` e na tabela final.

| Ferramenta | Para que serve | Licença | Dependências | Recursos medidos | Limites | Decisão |
|---|---|---|---|---|---|---|
| **OSV-Scanner 2.7.0** | SCA: dependências com advisory (OSV) | Apache-2.0 | binário Go estático | Juice Shop lockfile (1149 pacotes): 1,9 s, 63 MB | Consulta **online** api.osv.dev (envia nome+versão dos pacotes, não o código); offline exige `--offline --download-offline-databases` | **Integrado** (agente `sca`, backend 1). Detectou o GT `knownVulnerableComponentChallenge` (sanitize-html 1.4.2, express-jwt 0.1.3, jsonwebtoken 0.4.0) — núcleo não tinha SCA |
| **Trivy 0.76.1** | SCA, misconfig IaC, imagens | Apache-2.0 | binário Go; DB baixada (ghcr.io) | vuln: 0,2 s/123 MB; misconfig terraform: 0,7 s/194 MB | DB precisa download inicial; `--skip-db-update` depois | **Integrado como backend offline 2 do `sca`**. Misconfig: acha os 4 itens GT cloud que o núcleo já acha + 13 extras (ex.: RDS sem criptografia) fora do GT → não conta como cobertura medida; disponível como verificação cruzada manual |
| **Grype 0.121.1** | SCA | Apache-2.0 | binário Go; DB (~46 s de download) | 3,1 s, 4,4 s CPU, 211 MB | 30 pacotes vs 35 do OSV; mais pesado | **Backend 3 do `sca`** (fallback offline) |
| **Syft 1.56.0** | Gera SBOM | Apache-2.0 | binário Go | 1,1 s, 200 MB | Só inventário, não acha vulnerabilidade | Instalado, **não integrado** (sem cobertura nova); útil para entregar SBOM ao cliente |
| **Gitleaks 8.30.1** | Segredos em código/git | MIT | binário Go | Juice Shop (sem node_modules): 0,4 s, 59 MB, 20 hits; labdata: 1 hit | Todos os arquivos com hit também são achados pelo agente `code` nativo (33 achados de segredo); no labdata achou 1 de 9 itens GT (nativo: 9/9) | **Não integrado**: nenhuma cobertura adicional medida |
| **Nuclei** | Templates HTTP | MIT | binário Go + templates | ~580 s por lab (1.1) | Muitos hits sem reprodução | Já integrado na 1.1 (achados ficam "suspeita" até reprodução) |
| **Nmap** | Descoberta de portas/serviços | NPSL (não é OSI pura; uso interno ok, redistribuição restrita) | binário | — | Só 127.0.0.1 aqui | Já integrado na 1.0/1.1 (agente `network`), sem mudança |
| **MobSF** | Análise APK/IPA | GPL-3.0 | Python + JDK para JADX | servidor local :8000 | Sem Java no box: só manifesto (13 achados); JADX bloqueado pelo check de adulteração (não contornado) | Já integrado na 1.1 como corroboração |
| **YARA (yara-python 4.5.4)** | Regras de padrão em binários | BSD-3 | lib C via pip | instalado | Sem regras próprias do domínio não acha nada; escrever regras = detecção nossa, não da ferramenta | **Não integrado** [sem cobertura medida]; candidato para malware/APK na 2.x |
| **OWASP ZAP** | DAST web | Apache-2.0 | **Java 17+**, ~500 MB | não medido | Sem Java/apt no box | **Não integrado** [não testado]; avaliar com JDK portátil (Temurin, grátis) |
| **Prowler** | Auditoria de conta cloud real (AWS/Azure/GCP) | Apache-2.0 | pip, credenciais da conta | não medido | Precisa credenciais reais da nuvem do cliente; lab é 127.0.0.1 | **Não integrado**; só sob autorização formal e credencial read-only do cliente |
| **Ghidra** | Engenharia reversa | Apache-2.0 | Java 21, ~1,5 GB | não medido | Interativo; sem Java | **Não integrado** [não testado] |
| **JADX** | Decompilar APK | Apache-2.0 | Java | não medido | Sem Java | **Não integrado** (o analisador APK próprio + androguard cobrem o lab: 13/25 InsecureBankv2) |
| **Garak** | Sondas contra LLM | Apache-2.0 | pip pesado (torch/transformers) | não medido | Exige um LLM-alvo rodando; o lab de IA é estático | **Não integrado** [não testado] |
| **DefectDojo** | Gestão de vulnerabilidades | BSD-3 | Django + Postgres + Redis (Docker) | não medido | Sem Docker; o Control 1.0 já cobre histórico/achados | **Não integrado**; exportar JSON compatível é opção futura |

## Agente `sca` (novo, aditivo)
- Arquivo `cyberswarm/agents/sca.py`; check `sca.vulnerable_dependency` (high, CWE-1395) em `checks.py`; import em `registry.py`.
  São as **únicas mudanças no núcleo** nesta etapa (documentadas; nada existente foi alterado em comportamento).
- Backend: OSV-Scanner → Trivy → Grype (o primeiro instalado e não desativado por `CYBERSWARM_DISABLE_TOOLS`).
- Prova: linha do lockfile com nome+versão (re-verificada pelo `validate`, vira "confirmado") + id do advisory.
  Pacote que a ferramenta cita mas não aparece no arquivo é **descartado** (teste `test_sca_agent_with_fake_tool`).
- Auditoria registra `tool_exec` com `online=true` quando usa OSV (dados de pacotes saem para api.osv.dev). Para cliente que
  não permite, desativar: `CYBERSWARM_DISABLE_TOOLS=osv-scanner` (usa Trivy/Grype offline).
- Resultado medido (Juice Shop lockfile): OSV 35 pacotes, Trivy 31, Grype 30; os três acham os 3 pacotes do GT.
  Recall Juice Shop sobe 1 item (knownVulnerableComponentChallenge) **na análise de código** — é análise estática do
  repositório, não do serviço rodando. Itens `typosquattingNpmChallenge`/`supplyChainAttackChallenge` **não** detectados.

## Benchmarks (subprocesso isolado, os.wait4)
| Tipo | Nome | Alvo | Parede s | CPU s | RAM máx MB | Obs |
|---|---|---|---|---|---|---|
| agente | code | labdata/src | 0,12 | 0,11 | 32 | 6 achados |
| agente | cloud | labdata/terraform | 0,12 | 0,11 | 32 | 7 |
| agente | mobile | labdata/android | 0,12 | 0,11 | 33 | 6 |
| agente | ios | labdata/ios | 0,10 | 0,10 | 32 | 5 |
| agente | code | juice-shop/routes | 0,14 | 0,13 | 33 | 8 |
| agente | sca (osv) | lockfile Juice Shop | 2,25 | 0,57 | 63 | 35 |
| agente | api | labdata/openapi.json | — | — | — | requer servidor de API do lab ativo (rc=1 sem ele) |
| ferramenta | gitleaks | juice-shop | 0,40 | 0,39 | 59 | |
| ferramenta | osv-scanner | lockfile | 1,93 | 0,36 | 63 | rede |
| ferramenta | trivy vuln | lockfile | 0,18 | 0,23 | 123 | DB local |
| ferramenta | trivy misconfig | terraform | 0,73 | 1,11 | 194 | |
| ferramenta | grype | lockfile | 3,14 | 4,37 | 211 | |
| ferramenta | syft | lockfile | 1,11 | 1,12 | 200 | |

Medição única por linha (sem repetição estatística); maxrss inclui o interpretador Python (~30 MB de base).
Downloads com SHA256 conferido contra o checksums.txt oficial de cada release: ver `scripts/fetch_labs.sh`.
