# Checklist de segurança — CyberSwarm Control 2.0

Marque após verificar. Itens com teste automático citam o nome.

## Autenticação e sessão
- [x] Senha ≥ 10 chars, scrypt (`test_scrypt_hash`)
- [x] Cookie `HttpOnly; SameSite=Strict`; com `--tls`/`--secure-cookie` também `Secure`
- [x] Token de sessão só como SHA-256 no banco (`test_session_token_stored_hashed`)
- [x] Bloqueio após 5 falhas / 15 min (`test_bruteforce_limit`)
- [x] Sem enumeração de usuário (`test_unknown_user_no_enumeration`)
- [ ] Rotação periódica de sessão em uso longo — parcial (nova sessão a cada login)
- [x] Timeout de sessão 12 h (`SESSION_TTL`)

## Autorização
- [x] Owner vs viewer (`test_viewer_is_read_only`)
- [x] Separação por cliente (`test_client_separation`)
- [x] Escopo validado pelo núcleo antes de criar missão
- [x] Teste ativo fora do lab exige aprovação + justificativa (`test_approval_flow_…`)

## Transporte
- [x] HTTPS com cert autoassinado (`--tls`, `test_tls_self_signed`)
- [ ] Let's Encrypt / Cloudflare Tunnel — documentado, [não testado] em produção
- [x] CSP `script-src 'self'`, sem script inline

## Superfície
- [x] Sem endpoint de shell/comando (`test_no_command_execution_endpoint`)
- [x] CSRF + Origin em mutações
- [x] Corpo JSON ≤ 64 KB; Content-Type exigido
- [x] Chaves de IA nunca devolvidas ao frontend (`test_settings_no_key_echo`)
- [x] Bind padrão 127.0.0.1; LAN exige `--allow-lan`

## Auditoria e evidência
- [x] Trilha com hash encadeado
- [x] Achado "confirmado" só com prova re-verificada
- [x] Token de aprovação nunca no navegador

## Operação
- [x] Worker daemon independente do navegador
- [x] Retomada após kill (até N tentativas)
- [x] Modo determinístico sem IA
