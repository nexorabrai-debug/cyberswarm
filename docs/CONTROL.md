# CyberSwarm Control 1.0 — painel PWA (pt-BR)

Painel web instalável no celular para acompanhar e aprovar auditorias do CyberSwarm/Hacker AI.
**Não tem terminal nem endpoint de comando**: o painel só cria *missões* (objetivo + cliente + escopo já registrado) que o
worker executa reaproveitando o núcleo (planner, Orchestrator, ApprovalGate, Audit, relatórios). Teste:
`test_no_command_endpoint`.

## Instalar e iniciar
```bash
pip install -e .                       # ou: python3 -m cyberswarm ...
cyberswarm control init --data ~/cs-control
CONTROL_PASSWORD='uma-senha-longa' cyberswarm control adduser --data ~/cs-control --user dono --role owner
cyberswarm control adduser --data ~/cs-control --user cliente1 --role viewer --clients-only cliente-a   # pede a senha
cyberswarm control serve --data ~/cs-control            # http://127.0.0.1:8770
```
Senha: mínimo 10 caracteres, guardada com scrypt (n=2^14). O banco (SQLite) fica com permissão 600.

## Papéis
| Papel | Pode |
|---|---|
| owner | tudo: clientes/escopos, missões, aprovar/negar (com justificativa), ferramentas, finanças, usuários |
| viewer | ler painel, achados, relatórios e auditoria; com `--clients-only` vê só os clientes listados |

## Segurança implementada (e testada em `tests/test_control.py`)
- Sessão em cookie `HttpOnly; SameSite=Strict` (12 h); token guardado só como sha256 no servidor; `Secure` com `--secure-cookie`.
- Nenhuma senha/chave no frontend; o token CSRF fica só em memória da página.
- Toda rota `/api/` exige sessão (exceto login); mutações exigem cabeçalho CSRF + Origin igual + JSON (senão 415); corpo ≤ 64 KB.
- Login: 5 falhas em 15 min por IP ou usuário → 429; usuário inexistente gasta o mesmo tempo (sem enumeração).
- CSP `script-src 'self'`, sem script inline; HTML escapado no cliente.
- Separação por cliente: `data/clients/<id>/jobs/<job>/`; comparação de execuções só dentro do mesmo cliente.
- Alvo não-lab ativo cria aprovação pendente; o token de aprovação nunca vai ao navegador. Tudo vai para a auditoria com cadeia de hash.
- Finanças: só lançamentos manuais (nenhuma integração de pagamento).

## Acesso pelo celular
| Forma | Como | Estado |
|---|---|---|
| Termux no próprio Android | `cyberswarm control serve` e abrir `http://127.0.0.1:8770` | testado no box (Chrome 390 px) — no Termux [não testado] |
| Túnel SSH | `ssh -L 8770:127.0.0.1:8770 usuario@servidor` e abrir `http://127.0.0.1:8770` no celular (app SSH) | recomendado; servidor continua em 127.0.0.1 |
| Rede local (Wi-Fi) | `cyberswarm control serve --host 0.0.0.0 --allow-lan` | funciona com login, mas é **HTTP sem criptografia** na rede e o PWA não instala (service worker exige HTTPS ou localhost). Só em rede confiável |
| Cloudflare Tunnel (grátis) | `cloudflared tunnel --url http://127.0.0.1:8770` + `--secure-cookie` | [não testado] |
| Tailscale (grátis p/ uso pessoal) | `tailscale serve 8770` + `--secure-cookie` | [não testado] |

Sem `--allow-lan`, iniciar em endereço diferente de 127.0.0.1 é recusado. Nunca exponha sem HTTPS e senha forte.

## PWA
`manifest.json` (standalone, ícones 192/512 + maskable) e `sw.js` (guarda só a casca estática; **nunca** guarda `/api/`).
Chrome não acusou erro de manifesto nem de instalabilidade em 127.0.0.1.

## Limites
- Servidor `ThreadingHTTPServer` da biblioteca padrão: adequado para uso pessoal/pequena equipe, não para internet aberta.
- Sem 2FA nem recuperação de senha (recriar com `adduser`).
- Telas: login, painel, missões/tarefas, aprovações, clientes/escopos, auditoria, achados com evidência, comparação, PDF,
  ferramentas, logs, finanças.
