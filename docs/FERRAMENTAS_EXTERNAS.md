# Ferramentas externas no Hacker AI 1.1 (nmap, nuclei, MobSF)

Revisão de requisitos e de segurança. **Regra principal:** quando uma ferramenta aponta algo, isso é só uma **suspeita**. O achado só vira **confirmado** quando o validador do CyberSwarm reproduz a evidência por conta própria.

## Versões e origem (todas gratuitas/OSS)
| Ferramenta | Versão | Licença | Instalação nesta máquina |
|---|---|---|---|
| nmap | 7.95 (Debian) | NPSL | O apt estava bloqueado, então baixamos os `.deb` oficiais e extraímos com `dpkg -x` (`scripts/fetch_labs.sh`) |
| nuclei | v3.11.1 | MIT | Binário oficial do GitHub (ProjectDiscovery) + nuclei-templates |
| MobSF | 4.6.4 | GPL-3.0 | `uv pip install mobsf` num venv Python 3.12; JRE Temurin 25 |
| androguard | 4.1.4 | Apache-2.0 | venv `~/.cyberswarm-tools` (análise de APK própria, offline) |

## Trava de escopo (`extval/tools_ext.py: scope_lock`)
- Toda URL passa antes pelo `Scope.check_url` do núcleo.
- Sem cliente autorizado, só são aceitos `127.0.0.1`/`localhost`. Para um host externo, é obrigatório ter um registro válido em `clients.json`, e o termo não pode estar vencido.
- O MobSF só aceita uma `MOBSF_URL` local. Qualquer outra dá `PermissionError` (há teste para isso).
- Os hits do nuclei fora do **mesmo host:porta** do alvo são descartados e registrados no audit (`tool_hit_discarded`). Motivo: numa rodada manual inicial, um template acessou `127.0.0.1:6080` (noVNC desta máquina), que estava fora do alvo. Esse foi o incidente que levou à trava.

## Limites do nuclei
`-rl 10 -c 5 -timeout 3 -retries 0 -no-interactsh -dr -disable-update-check`
- Tags permitidas: `exposure,misconfig,graphql,swagger,config,debug,api,logs,disclosure`.
- Tags excluídas: `intrusive,dos,fuzz,bruteforce,rce,sqli,xss,lfi,ssrf,injection,default-login,auth-bypass,cve,oast,file-upload,takeover`.
- Há um tempo máximo por execução (padrão 600 s; opção `nuclei_timeout`). Se passar disso, o grupo de processos é morto e o resultado parcial é mantido (status `partial`).
- **Atenção:** alguns templates permitidos também enviam POST, por exemplo o de graphql batching. Isso é aceitável em laboratório local, mas **não** para um cliente sem autorização explícita para isso. Em cliente real, use `--no-nuclei` ou revise as tags.
- O `-no-interactsh` garante que nada sai para servidores OAST externos.

## nmap
Só roda com `-sT` (connect, sem root), limitado ao escopo e pelo agente `network` do núcleo.

## MobSF
- Análise estática por REST, com chave em `~/labs/mobsf.key` (permissão 600, fora do zip).
- **Limitação real:** a análise de código (JADX) falha com "Executable/Library Tampering Detected". O MobSF não reconhece o hash do jadx 1.5.6 instalado. **Não contornamos** essa checagem. Por isso só a análise do manifest do MobSF funcionou.
- Os hits do MobSF não trazem prova reproduzível. Ficam como `suspeita` e só passam a `confirmado` quando a nossa análise (androguard) tem um achado confirmado da mesma categoria (`corroborate`).

## Regras de evidência
| Origem | Como é confirmado |
|---|---|
| nuclei (cabeçalho ausente) | Um GET próprio confirma que o cabeçalho continua ausente |
| nuclei (demais) | GET próprio com HTTP 200, corpo diferente do *baseline* de soft-404 e, se o template extrai algo, esse dado presente no corpo |
| MobSF | Corroborado por um achado `apk.*` confirmado da mesma categoria |
| APK (nosso) | Prova de arquivo: linha + sha256. O validador do núcleo relê o artefato, e se o artefato for alterado o achado volta a `suspeita` (há teste) |
| hit não reproduzido | Fica como `suspeita`, com severidade limitada a média, e **não conta** como detecção nas métricas |
