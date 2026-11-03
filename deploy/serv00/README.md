# Deploy Serv00 (sem cartão)

Ver guia completo: `docs/IMPLANTACAO_SEM_CARTAO.md` § Serv00.

Scripts:
- `bootstrap.sh` — venv + install + init owner (correr no SSH)
- `start.sh` — sobe Control+workers em loop (screen/cron)
- `proxy.example.txt` — comandos `devil` para HTTPS
