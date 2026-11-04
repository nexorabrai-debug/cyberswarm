# Tabela de validação de gravidade (CyberSwarm 1.0 / Hacker AI)

Regras aplicadas pelo módulo `validation` (testadas em `tests/test_validation_compare.py`):

1. **A gravidade vem só desta tabela.** Cada `check_id` tem uma gravidade fixa em `cyberswarm/checks.py`. Se um agente mandar outra, ela é corrigida.
2. **Confirmado x Suspeita.**
   - `confirmado` exige evidência reproduzível: requisição + resposta HTTP capturadas, com o comando `curl`; ou handshake TLS observado, com o comando `openssl`; ou arquivo + número da linha, e essa linha é **lida de novo do disco** e conferida por hash.
   - Sem isso, o achado é `suspeita`.
3. **Suspeita nunca passa de "medium".** Uma suspeita de gravidade alta ou crítica é rebaixada para medium até alguém confirmar.
4. **Prioridade:** critical = P1, high = P2, medium = P3, low = P4, info = P5. Dentro da mesma gravidade, os confirmados vêm antes.
5. **Fingerprint (comparação entre análises)** = sha256(agente | check_id | gravidade | título |
|---|---|---|
| `ai.dangerous_tool` | high | Agente de IA com ferramenta perigosa (shell/exec) habilitada |
| `ai.no_output_filter` | medium | Saída do modelo sem filtro/validação |
| `ai.prompt_injection` | high | Template de prompt concatena entrada do usuário sem delimitação |
| `ai.secret_in_prompt` | critical | Segredo embutido em prompt/configuração de IA |
| `ai.system_prompt_disclosure` | medium | Prompt não proíbe revelar instruções internas e expõe dados internos |
| `android.allow_backup` | medium | Backup do app Android liberado |
| `android.cleartext` | medium | Tráfego HTTP sem criptografia permitido (Android) |
| `android.debuggable` | high | App Android com debuggable=true |
| `android.exported` | medium | Componente Android exportado sem permissão |
| `api.bola` | high | Broken Object Level Authorization |
| `api.excessive_data` | high | API retorna campos sensíveis (senha/hash/segredo) em resposta GET |
| `api.jwt_password_hash` | high | JWT de sessão embute hash de senha |
| `api.jwt_weak_key` | critical | JWT aceito com chave fraca/conhecida |
| `api.mass_assignment` | high | Mass assignment eleva privilégio (admin) |
| `api.no_security_schemes` | medium | Especificação da API sem esquemas de autenticação |
| `api.ratelimit.doc` | low | Rate limit não documentado |
| `api.ratelimit.live` | low | Resposta real sem cabeçalho de rate limit |
| `api.sqli` | critical | Injeção SQL em parâmetro de API |
| `api.unauth.public` | low | Endpoint de leitura sem autenticação |
| `api.unauth.sensitive` | high | Endpoint sensível ou de escrita sem autenticação |
| `api.unauth_password_change` | critical | Troca de senha de outro usuário (BOLA) |
| `api.user_enum` | medium | Enumeração de usuário/senha via mensagens distintas |
| `api.verbose_error.doc` | medium | Erro verboso documentado (stack trace) |
| `api.verbose_error.live` | medium | Erro verboso em execução (stack trace na resposta) |
| `apk.allowbackup` | medium | APK com android:allowBackup=true |
| `apk.backdoor_string` | high | Credencial/usuário especial embutido no código (possível backdoor) |
| `apk.cleartext_http` | medium | App monta URLs http:// (texto claro) |
| `apk.debuggable` | high | APK com android:debuggable=true |
| `apk.exported.activity` | medium | Activity exportada sem permissão |
| `apk.exported.provider` | high | Content provider exportado sem permissão |
| `apk.exported.receiver` | medium | Broadcast receiver exportado sem permissão |
| `apk.external_storage` | medium | App grava/lê no armazenamento externo (SD card) |
| `apk.hardcoded_key` | high | Chave criptográfica embutida no código |
| `apk.log_sensitive` | medium | Log de dados sensíveis (Log.d em fluxo de login) |
| `apk.old_minsdk` | low | minSdkVersion muito antigo (< 21) |
| `apk.prefs_creds` | high | Credenciais gravadas em SharedPreferences |
| `apk.receiver_sms` | high | Receiver exportado envia SMS com dados recebidos no intent |
| `apk.static_iv` | medium | IV fixo/estático em cifra CBC |
| `apk.webview_js` | medium | WebView com JavaScript habilitado carregando conteúdo |
| `cloud.s3_block_disabled` | high | Bloqueio de acesso público do S3 desativado |
| `cloud.s3_public_acl` | high | Bucket S3 público (ACL public-read) |
| `cloud.sg_admin_open` | critical | Porta administrativa aberta para a internet (0.0.0.0/0) |
| `cloud.sg_open` | medium | Security group aberto para 0.0.0.0/0 |
| `codesec.debug` | medium | Modo debug ligado em código de aplicação |
| `codesec.eval` | high | Uso de eval/exec com dados potencialmente externos |
| `codesec.external` | medium | Achado de ferramenta SAST externa |
| `codesec.pickle` | high | Desserialização insegura (pickle/marshal) |
| `codesec.shell` | high | subprocess com shell=True |
| `codesec.sql_concat` | high | SQL montado por concatenação/format |
| `codesec.tls_verify_off` | high | Verificação de certificado TLS desativada (verify=False) |
| `codesec.weak_hash` | medium | Hash fraco (MD5/SHA1) em contexto de segurança |
| `codesec.yaml_load` | medium | yaml.load sem SafeLoader |
| `ext.mobsf.critical` | critical | Achado do MobSF (análise estática) |
| `ext.mobsf.high` | high | Achado do MobSF (análise estática) |
| `ext.mobsf.info` | info | Achado do MobSF (análise estática) |
| `ext.mobsf.low` | low | Achado do MobSF (análise estática) |
| `ext.mobsf.medium` | medium | Achado do MobSF (análise estática) |
| `ext.nuclei.critical` | critical | Achado do nuclei (template OSS) |
| `ext.nuclei.high` | high | Achado do nuclei (template OSS) |
| `ext.nuclei.info` | info | Achado do nuclei (template OSS) |
| `ext.nuclei.low` | low | Achado do nuclei (template OSS) |
| `ext.nuclei.medium` | medium | Achado do nuclei (template OSS) |
| `gql.aliases` | medium | Aliases GraphQL sem limite |
| `gql.batching` | medium | GraphQL array batching habilitado |
| `gql.deep_recursion` | medium | Recursão GraphQL sem limite aparente |
| `gql.detect` | info | Endpoint GraphQL descoberto |
| `gql.fingerprint` | info | Fingerprint do motor GraphQL via erro |
| `gql.graphiql` | low | Interface GraphiQL/IDE exposta |
| `gql.introspection` | medium | Introspecção GraphQL habilitada |
| `gql.stacktrace` | medium | GraphQL retorna stack trace em erros |
| `gql.suggestions` | low | GraphQL sugere nomes de campos em erros |
| `ios.ats_disabled` | high | ATS desativado (NSAllowsArbitraryLoads) |
| `ios.ats_webcontent` | medium | ATS desativado em WebView |
| `ios.file_sharing` | low | Compartilhamento de arquivos do app ativo (iOS) |
| `ios.insecure_domain` | medium | HTTP inseguro permitido para domínio (iOS) |
| `ios.old_tls_domain` | medium | TLS antigo permitido para domínio (iOS) |
| `ios.url_scheme` | info | URL scheme customizado (deep link) |
| `lab.webgoat.insecure_login` | medium | WebGoat: login inseguro da lição aceito |
| `lab.webgoat.sqli` | high | WebGoat: SQL concatenada com entrada do usuário |
| `net.open.cleartext` | low | Porta de serviço em texto claro aberta |
| `net.open.datastore` | high | Banco de dados/cache acessível por TCP |
| `net.open.other` | info | Porta TCP aberta |
| `net.open.tls` | info | Porta TLS aberta |
| `poc.cors_creds` | high | PoC de laboratório: CORS reflete origem arbitrária com credenciais (reproduzido) |
| `poc.env_exposure` | critical | PoC de laboratório: arquivo .env exposto reproduzido 2x com conteúdo idêntico |
| `poc.git_exposure` | high | PoC de laboratório: repositório .git exposto reproduzido |
| `sca.vulnerable_dependency` | high | Dependência com vulnerabilidade conhecida |
| `secret.assignment` | high | Senha ou segredo atribuído diretamente no código |
| `secret.aws_key` | critical | Chave de acesso AWS no código |
| `secret.github_token` | critical | Token do GitHub no código |
| `secret.google_api_key` | high | Chave de API do Google no código |
| `secret.high_entropy` | medium | Texto de alta entropia (possível segredo) |
| `secret.jwt` | medium | Token JWT fixo no código |
| `secret.llm_api_key` | critical | Chave de API de provedor de IA (sk-...) no código/prompt |
| `secret.private_key` | critical | Chave privada no código |
| `secret.slack_token` | high | Token do Slack no código |
| `secret.stripe_key` | critical | Chave secreta Stripe live no código |
| `tls.expired` | critical | Certificado expirado |
| `tls.expiring` | medium | Certificado expira em menos de 30 dias |
| `tls.hostname_mismatch` | high | Certificado não corresponde ao nome do host |
| `tls.hsts` | medium | HSTS ausente em site HTTPS |
| `tls.old_protocol` | high | Protocolo TLS obsoleto aceito (TLS 1.0/1.1) |
| `tls.self_signed` | high | Certificado autoassinado |
| `web.access_log` | high | Log de acesso exposto via HTTP |
| `web.api_docs_exposed` | low | Documentação de API (Swagger/OpenAPI) pública |
| `web.confidential_doc` | medium | Documento confidencial servido em /ftp |
| `web.cookie.httponly` | medium | Cookie sem flag HttpOnly |
| `web.cookie.samesite` | low | Cookie sem atributo SameSite |
| `web.cookie.secure` | medium | Cookie sem flag Secure em HTTPS |
| `web.cors.reflect` | medium | CORS reflete qualquer origem |
| `web.cors.reflect_creds` | high | CORS reflete qualquer origem com credenciais |
| `web.cors.wildcard` | low | CORS aberto (Access-Control-Allow-Origin: *) |
| `web.dirlisting` | medium | Listagem de diretório habilitada |
| `web.error_stacktrace` | medium | Erro com stack trace exposto |
| `web.exposed.backup` | medium | Arquivo de backup exposto |
| `web.exposed.env` | critical | Arquivo .env exposto publicamente |
| `web.exposed.git` | high | Repositório .git exposto |
| `web.header.csp` | medium | Cabeçalho Content-Security-Policy ausente |
| `web.header.referrer` | low | Cabeçalho Referrer-Policy ausente |
| `web.header.xcto` | low | Cabeçalho X-Content-Type-Options ausente |
| `web.header.xfo` | low | Cabeçalho X-Frame-Options ausente |
| `web.methods.risky` | medium | Métodos HTTP de escrita anunciados (PUT/DELETE/PATCH) |
| `web.methods.trace` | high | Método TRACE anunciado |
| `web.metrics_exposed` | medium | Endpoint de métricas (Prometheus) exposto sem autenticação |
| `web.no_https` | medium | Site acessível sem HTTPS |
| `web.score_board` | info | Rota de score-board referenciada no front |
| `web.server_version` | low | Versão do servidor exposta |

Comando: `cyberswarm severity-table` imprime a tabela abaixo.

| check_id | gravidade | título |
|---|---|---|
| `ai.dangerous_tool` | high | Agente de IA com ferramenta perigosa (shell/exec) habilitada |
| `ai.no_output_filter` | medium | Saída do modelo sem filtro/validação |
| `ai.prompt_injection` | high | Template de prompt concatena entrada do usuário sem delimitação |
| `ai.secret_in_prompt` | critical | Segredo embutido em prompt/configuração de IA |
| `ai.system_prompt_disclosure` | medium | Prompt não proíbe revelar instruções internas e expõe dados internos |
| `android.allow_backup` | medium | Backup do app Android liberado |
| `android.cleartext` | medium | Tráfego HTTP sem criptografia permitido (Android) |
| `android.debuggable` | high | App Android com debuggable=true |
| `android.exported` | medium | Componente Android exportado sem permissão |
| `api.bola` | high | Broken Object Level Authorization |
| `api.excessive_data` | high | API retorna campos sensíveis (senha/hash/segredo) em resposta GET |
| `api.jwt_weak_key` | critical | JWT aceito com chave fraca/conhecida |
| `api.no_security_schemes` | medium | Especificação da API sem esquemas de autenticação |
| `api.ratelimit.doc` | low | Rate limit não documentado |
| `api.ratelimit.live` | low | Resposta real sem cabeçalho de rate limit |
| `api.unauth.public` | low | Endpoint de leitura sem autenticação |
| `api.unauth.sensitive` | high | Endpoint sensível ou de escrita sem autenticação |
| `api.verbose_error.doc` | medium | Erro verboso documentado (stack trace) |
| `api.verbose_error.live` | medium | Erro verboso em execução (stack trace na resposta) |
| `apk.allowbackup` | medium | APK com android:allowBackup=true |
| `apk.backdoor_string` | high | Credencial/usuário especial embutido no código (possível backdoor) |
| `apk.cleartext_http` | medium | App monta URLs http:// (texto claro) |
| `apk.debuggable` | high | APK com android:debuggable=true |
| `apk.exported.activity` | medium | Activity exportada sem permissão |
| `apk.exported.provider` | high | Content provider exportado sem permissão |
| `apk.exported.receiver` | medium | Broadcast receiver exportado sem permissão |
| `apk.external_storage` | medium | App grava/lê no armazenamento externo (SD card) |
| `apk.hardcoded_key` | high | Chave criptográfica embutida no código |
| `apk.log_sensitive` | medium | Log de dados sensíveis (Log.d em fluxo de login) |
| `apk.old_minsdk` | low | minSdkVersion muito antigo (< 21) |
| `apk.prefs_creds` | high | Credenciais gravadas em SharedPreferences |
| `apk.receiver_sms` | high | Receiver exportado envia SMS com dados recebidos no intent |
| `apk.static_iv` | medium | IV fixo/estático em cifra CBC |
| `apk.webview_js` | medium | WebView com JavaScript habilitado carregando conteúdo |
| `cloud.s3_block_disabled` | high | Bloqueio de acesso público do S3 desativado |
| `cloud.s3_public_acl` | high | Bucket S3 público (ACL public-read) |
| `cloud.sg_admin_open` | critical | Porta administrativa aberta para a internet (0.0.0.0/0) |
| `cloud.sg_open` | medium | Security group aberto para 0.0.0.0/0 |
| `codesec.debug` | medium | Modo debug ligado em código de aplicação |
| `codesec.eval` | high | Uso de eval/exec com dados potencialmente externos |
| `codesec.external` | medium | Achado de ferramenta SAST externa |
| `codesec.pickle` | high | Desserialização insegura (pickle/marshal) |
| `codesec.shell` | high | subprocess com shell=True |
| `codesec.sql_concat` | high | SQL montado por concatenação/format |
| `codesec.tls_verify_off` | high | Verificação de certificado TLS desativada (verify=False) |
| `codesec.weak_hash` | medium | Hash fraco (MD5/SHA1) em contexto de segurança |
| `codesec.yaml_load` | medium | yaml.load sem SafeLoader |
| `ext.mobsf.critical` | critical | Achado do MobSF (análise estática) |
| `ext.mobsf.high` | high | Achado do MobSF (análise estática) |
| `ext.mobsf.info` | info | Achado do MobSF (análise estática) |
| `ext.mobsf.low` | low | Achado do MobSF (análise estática) |
| `ext.mobsf.medium` | medium | Achado do MobSF (análise estática) |
| `ext.nuclei.critical` | critical | Achado do nuclei (template OSS) |
| `ext.nuclei.high` | high | Achado do nuclei (template OSS) |
| `ext.nuclei.info` | info | Achado do nuclei (template OSS) |
| `ext.nuclei.low` | low | Achado do nuclei (template OSS) |
| `ext.nuclei.medium` | medium | Achado do nuclei (template OSS) |
| `gql.batching` | medium | GraphQL array batching habilitado |
| `gql.graphiql` | low | Interface GraphiQL/IDE exposta |
| `gql.introspection` | medium | Introspecção GraphQL habilitada |
| `gql.stacktrace` | medium | GraphQL retorna stack trace em erros |
| `gql.suggestions` | low | GraphQL sugere nomes de campos em erros |
| `ios.ats_disabled` | high | ATS desativado (NSAllowsArbitraryLoads) |
| `ios.ats_webcontent` | medium | ATS desativado em WebView |
| `ios.file_sharing` | low | Compartilhamento de arquivos do app ativo (iOS) |
| `ios.insecure_domain` | medium | HTTP inseguro permitido para domínio (iOS) |
| `ios.old_tls_domain` | medium | TLS antigo permitido para domínio (iOS) |
| `ios.url_scheme` | info | URL scheme customizado (deep link) |
| `net.open.cleartext` | low | Porta de serviço em texto claro aberta |
| `net.open.datastore` | high | Banco de dados/cache acessível por TCP |
| `net.open.other` | info | Porta TCP aberta |
| `net.open.tls` | info | Porta TLS aberta |
| `poc.cors_creds` | high | PoC de laboratório: CORS reflete origem arbitrária com credenciais (reproduzido) |
| `poc.env_exposure` | critical | PoC de laboratório: arquivo .env exposto reproduzido 2x com conteúdo idêntico |
| `poc.git_exposure` | high | PoC de laboratório: repositório .git exposto reproduzido |
| `sca.vulnerable_dependency` | high | Dependência com vulnerabilidade conhecida |
| `secret.assignment` | high | Senha ou segredo atribuído diretamente no código |
| `secret.aws_key` | critical | Chave de acesso AWS no código |
| `secret.github_token` | critical | Token do GitHub no código |
| `secret.google_api_key` | high | Chave de API do Google no código |
| `secret.high_entropy` | medium | Texto de alta entropia (possível segredo) |
| `secret.jwt` | medium | Token JWT fixo no código |
| `secret.llm_api_key` | critical | Chave de API de provedor de IA (sk-...) no código/prompt |
| `secret.private_key` | critical | Chave privada no código |
| `secret.slack_token` | high | Token do Slack no código |
| `secret.stripe_key` | critical | Chave secreta Stripe live no código |
| `tls.expired` | critical | Certificado expirado |
| `tls.expiring` | medium | Certificado expira em menos de 30 dias |
| `tls.hostname_mismatch` | high | Certificado não corresponde ao nome do host |
| `tls.hsts` | medium | HSTS ausente em site HTTPS |
| `tls.old_protocol` | high | Protocolo TLS obsoleto aceito (TLS 1.0/1.1) |
| `tls.self_signed` | high | Certificado autoassinado |
| `web.api_docs_exposed` | low | Documentação de API (Swagger/OpenAPI) pública |
| `web.cookie.httponly` | medium | Cookie sem flag HttpOnly |
| `web.cookie.samesite` | low | Cookie sem atributo SameSite |
| `web.cookie.secure` | medium | Cookie sem flag Secure em HTTPS |
| `web.cors.reflect` | medium | CORS reflete qualquer origem |
| `web.cors.reflect_creds` | high | CORS reflete qualquer origem com credenciais |
| `web.cors.wildcard` | low | CORS aberto (Access-Control-Allow-Origin: *) |
| `web.dirlisting` | medium | Listagem de diretório habilitada |
| `web.error_stacktrace` | medium | Erro com stack trace exposto |
| `web.exposed.backup` | medium | Arquivo de backup exposto |
| `web.exposed.env` | critical | Arquivo .env exposto publicamente |
| `web.exposed.git` | high | Repositório .git exposto |
| `web.header.csp` | medium | Cabeçalho Content-Security-Policy ausente |
| `web.header.referrer` | low | Cabeçalho Referrer-Policy ausente |
| `web.header.xcto` | low | Cabeçalho X-Content-Type-Options ausente |
| `web.header.xfo` | low | Cabeçalho X-Frame-Options ausente |
| `web.methods.risky` | medium | Métodos HTTP de escrita anunciados (PUT/DELETE/PATCH) |
| `web.methods.trace` | high | Método TRACE anunciado |
| `web.metrics_exposed` | medium | Endpoint de métricas (Prometheus) exposto sem autenticação |
| `web.no_https` | medium | Site acessível sem HTTPS |
| `web.server_version` | low | Versão do servidor exposta |
