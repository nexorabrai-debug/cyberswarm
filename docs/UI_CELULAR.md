# Interface web local (celular)

`cyberswarm --out reports hacker ui --ui-port 8765`
- Escuta **somente em 127.0.0.1**, com servidor fixo nesse endereço (há teste).
- Na primeira vez gera um token aleatório, grava em `reports/ui_token` com permissão 600 e mostra o token na tela. Você também pode definir o token pela variável `CYBERSWARM_UI_TOKEN`.
- Para entrar, informe o token. A sessão usa cookie `HttpOnly; SameSite=Strict`, e scripts podem enviar `Authorization: Bearer`.
- As varreduras são iniciadas por POST com token CSRF e só aceitam laboratórios já registrados. Não é possível digitar uma URL qualquer.
- Cabeçalhos de segurança: CSP, X-Frame-Options DENY, nosniff e no-referrer. O layout é responsivo (print em 390 px: `hacker11-ui-mobile.png`).

## Acesso pelo celular — **NÃO TESTADO em aparelho real**
- **Termux (recomendado):** rode o CyberSwarm no próprio celular (veja o README, seção 6) e abra `http://127.0.0.1:8765` no navegador do celular. Assim nada fica exposto na rede.
- **Do PC para o celular:** use um túnel SSH a partir do celular (por exemplo `ssh -L 8765:127.0.0.1:8765 usuario@pc` no Termux) e abra `http://127.0.0.1:8765`.
- **Não** exponha a porta com `0.0.0.0` nem com túneis públicos (ngrok e semelhantes). O programa não oferece essa opção.
