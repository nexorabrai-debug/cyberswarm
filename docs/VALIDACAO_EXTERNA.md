# Validação externa — Hacker AI 1.1

Medido em 2026-11-03, nesta máquina, contra laboratórios oficiais rodando **somente em 127.0.0.1**. Tudo pode ser reproduzido com `scripts/fetch_labs.sh`, depois `scripts/start_labs.sh` e por fim `cyberswarm --out /tmp/full hacker validate --lab all --mode both`. A saída bruta fica em `extval_summary.json` e `extval_<lab>_<modo>.json`.

## Definições
- **Itens oficiais**: a lista publicada pelo projeto (desafios/lições/vulnerabilidades), em `cyberswarm/extval/data/gt_*.json`, com o link da fonte e a versão fixada.
- **Detectado**: um item oficial com pelo menos um achado **confirmado** (evidência reproduzida pelo nosso validador) que está mapeado para ele em `mapping.json`. Fomos nós que escrevemos esse mapeamento, então ele pode ser auditado.
- **Revocação** = detectados / itens oficiais.
- **Precisão estrita** = achados mapeados a um item oficial / total de achados. Achados confirmados que estão fora da lista oficial (cabeçalhos ausentes, por exemplo) são reais, mas **reduzem** esse número. Por isso ele é conservador.
- **Não reproduzido**: um hit de ferramenta que o validador não conseguiu reproduzir. Fica como `suspeita` e **não conta** como detecção.
- **Falso positivo**: os achados `confirmado` são reproduzidos de forma automática. **Não fizemos uma revisão manual completa**, então a taxa real de falso positivo entre os confirmados **não foi medida**. Os hits não reproduzidos (coluna própria) são tratados como possíveis falsos positivos.

## Resultados por laboratório (1.0 = só agentes do núcleo; 1.1 = probes + nmap + nuclei + APK/MobSF)
| Lab | modo | itens oficiais | detectados | revocação | achados | mapeados | confirmados não listados | não reproduzidos | precisão estrita | tempo |
|---|---|---|---|---|---|---|---|---|---|---|
| juice-shop | 1.0 | 116 | 0 | 0.0% | 6 | 0 | 6 | 0 | 0.0% | 0.4s |
| juice-shop | 1.1 | 116 | 2 | 1.7% | 18 | 3 | 15 | 0 | 16.7% | 583.21s |
| webgoat | 1.0 | 25 | 0 | 0.0% | 6 | 0 | 6 | 0 | 0.0% | 0.39s |
| webgoat | 1.1 | 25 | 0 | 0.0% | 10 | 0 | 9 | 1 | 0.0% | 582.86s |
| vampi | 1.0 | 9 | 0 | 0.0% | 7 | 0 | 7 | 0 | 0.0% | 0.39s |
| vampi | 1.1 | 9 | 2 | 22.2% | 47 | 6 | 41 | 0 | 12.8% | 584.0s |
| dvga | 1.0 | 23 | 0 | 0.0% | 8 | 0 | 8 | 0 | 0.0% | 0.39s |
| dvga | 1.1 | 23 | 2 | 8.7% | 28 | 2 | 19 | 7 | 7.1% | 575.44s |
| insecurebankv2 | 1.0 | 25 | 0 | 0.0% | 0 | 0 | 0 | 0 | 0.0% | 0.05s |
| insecurebankv2 | 1.1 | 25 | 13 | 52.0% | 33 | 27 | 2 | 4 | 81.8% | 11.69s |
| crapi | - | NÃO EXECUTADO | | | | | | | |

Os 4 labs web rodaram em paralelo com nuclei. Cada execução do nuclei levou cerca de 580 s, todas terminaram completas e 0 hits foram descartados por estarem fora da porta.

## O que foi detectado
- **juice-shop**: detectados = directoryListingChallenge, exposedMetricsChallenge; só ferramenta (não contam) = nenhum; fonte: https://github.com/juice-shop/juice-shop/blob/v20.3.0/data/static/challenges.yml
- **webgoat**: detectados = nenhum; só ferramenta (não contam) = nenhum; fonte: https://github.com/WebGoat/WebGoat/tree/v2026.4/src/main/java/org/owasp/webgoat/lessons
- **vampi**: detectados = excessive_data_exposure_through_debug_endpoint, lack_of_resources_rate_limiting; só ferramenta (não contam) = nenhum; fonte: https://github.com/erev0s/VAmPI#list-of-vulnerabilities
- **dvga**: detectados = graphiql_interface, graphql_introspection; só ferramenta (não contam) = aliases_based_attack, batch_query_attack, discovering_graphql, fingerprinting_graphql, graphql_field_suggestions; fonte: https://github.com/dolevf/Damn-Vulnerable-GraphQL-Application#scenarios
- **insecurebankv2**: detectados = android_backup_vulnerability, application_debuggable, developer_backdoors, flawed_broadcast_receivers, hardcoded_secrets, insecure_content_provider_access, insecure_http_connections, insecure_logging_mechanism, insecure_sdcard_storage, insecure_webview_implementation, local_encryption_issues, vulnerable_activity_components, weak_cryptography_implementation; só ferramenta (não contam) = nenhum; fonte: https://github.com/dineshshetty/Android-InsecureBankv2#readme

**Leitura honesta:** a revocação nos labs web fica entre 0% e 22%. A grande maioria dos itens oficiais exige exploração ativa (injeção, XSS, quebra de autenticação), e o CyberSwarm **não faz** isso por desenho. No APK (InsecureBankv2) a revocação foi de 52%, com análise estática real. **Nenhum laboratório isolado prova cobertura**, e nenhum número aqui deve ser apresentado como "cobertura de 100%".

## Viés declarado
- As probes genéricas da 1.1 (`discovery`, `graphql`, `apidata`) foram escritas **depois** de lermos as listas oficiais. O modo 1.0 serve de linha de base sem esse viés.
- No Juice Shop, a página de erro do Express usa `&nbsp;` e o regex de stack trace não a reconhece. **Deixamos como não detectado** e não ajustamos depois da medição.
- O MobSF não conseguiu analisar o código: o JADX foi bloqueado por "Executable/Library Tampering Detected" e **não contornamos** isso. Só a análise do manifest funcionou (13 itens). A detecção estática de IV fixo (static IV) **não foi implementada** de forma honesta (removemos um `or True`).
- A lista do InsecureBankv2 usada é só a parte "currently included" (25 itens).

## O que não rodou
- **crAPI**: precisa de Docker Compose com mais de 7 serviços. Docker e Podman não existem nesta máquina, e o apt está bloqueado (o proxy devolve 500). Clonamos o projeto apenas para pegar a lista de desafios (18 itens), sem medir nada.
- As alternativas DVWA (PHP/MySQL) não foram instaladas porque o apt está bloqueado. Rodamos VAmPI e DVGA no lugar.

## Recuperação de falhas (com as ferramentas reais) — `recovery.json`
| Experimento | tarefas | achados | tempo |
|---|---|---|---|
| timeout_nuclei_real | discovery=done, nuclei=partial | 1 | 20.03s |
| nuclei_real_morto_SIGKILL_15s | graphql=done, nuclei=partial | 2 | 15.02s |
| lab_fora_do_ar | graphql=done, discovery=error, discovery=done | 4 | 0.34s |
| estresse_80_tarefas_orcamento_padrao_300 | {'error': 36, 'done': 44} | 29 | 6.16s |
| estresse_80_tarefas_orcamento_5000 | {'done': 80} | 29 | 10.08s |

- Timeout de 20 s no nuclei real: o grupo de processos foi morto, a tarefa ficou `partial` e a outra tarefa terminou normalmente.
- `SIGKILL` externo no nuclei depois de 15 s: a tarefa ficou `partial`, com o que já tinha sido gravado preservado.
- Lab fora do ar (porta 5999): `error`, com 1 nova tentativa registrada no audit, e as outras tarefas seguiram.
- Estresse com 80 tarefas e 16 workers: usando o orçamento padrão de 300 requisições por análise, **36 tarefas foram bloqueadas** pelo limite de segurança do núcleo (`BudgetExceeded`). Isso é o comportamento esperado, e as tarefas falham fechadas. Com o orçamento elevado para 5000 (só em laboratório), as 80 ficaram `done` e o resultado sem duplicatas foi idêntico ao de uma execução em série (há teste).

## Segurança das ferramentas
Veja `FERRAMENTAS_EXTERNAS.md`. Resumo: um template do nuclei acessou 127.0.0.1:6080 numa rodada manual inicial, e agora a trava descarta hits fora do host:porta. Alguns templates do nuclei fazem POST, o que é aceitável só em laboratório local.

## Mudanças no núcleo estável (aditivas)
- `cyberswarm/checks.py`: novas entradas de catálogo (`web.dirlisting`, `web.metrics_exposed`, `gql.*`, `apk.*`, `ext.nuclei.*`, `ext.mobsf.*`...). Nenhuma entrada existente foi alterada. `SEVERIDADE.md` foi regerado.
- `cyberswarm/cli.py`: ações `hacker validate|labs|ui` e as opções delas. Nada existente mudou.
- Testes: `tests/test_extval.py` (20 testes), com a suíte completa passando.
