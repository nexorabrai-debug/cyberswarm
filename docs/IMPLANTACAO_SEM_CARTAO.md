# Implantação CyberSwarm Control **sem cartão** (2026-11-03, America/Sao_Paulo)

Oracle Always Free / GCP free pedem cartão (mesmo só para verificação). O owner **proíbe qualquer cartão**.  
Este documento lista opções verificadas em páginas oficiais e prepara os **2 melhores caminhos** com configs em `deploy/`.

**Nenhuma conta foi criada por este agente.**

## Ranking (só opções sem cartão obrigatório)

| # | Plataforma | Cartão? | HTTPS | Disco persistente / SQLite | Worker em background | Sleep | Outbound p/ scanners | Fonte oficial |
|---|---|---|---|---|---|---|---|---|
| 1 | **Serv00** | Não (grátis) | Sim (Let’s Encrypt + proxy) | **Sim** 3 GB SSD | **Sim** (15 processos; `screen`/`nohup`/cron) | Passenger WWW dorme 24h sem hits; processo próprio **não** | Normalmente aberto; abuso pode banir IP | [serv00.com](https://www.serv00.com/), [docs Python](https://docs.serv00.com/Python/), [WWW proxy](https://docs.serv00.com/WWW/) |
| 2 | **Render Free** web | **Não** no signup | Sim (managed TLS) | **Não** no free (FS efémero; perde SQLite no sleep/redeploy) | Só **in-process** enquanto acordado; “Background Worker” não é free | **15 min** sem HTTP/WS → spin-down ~1 min cold start; 750 h/mês | Tráfego iniciado pelo serviço muito alto → suspensão | [render.com/docs/free](https://render.com/docs/free) |
| 3 | GitHub Codespaces | Não até esgotar quota | Port forward público `*.app.github.dev` (HTTP; HTTPS público→privado) | Disco do codespace enquanto existir | Sim enquanto codespace ativo | Idle ~30 min para; **120 core-h/mês** Free (~60 h em 2-core) | Aberto | [Codespaces billing](https://docs.github.com/en/billing/concepts/product-billing/github-codespaces), [ports](https://docs.github.com/en/codespaces/developing-in-a-codespace/forwarding-ports-in-your-codespace) |
| — | Alwaysdata Free | Signup pode exigir cartão anti-abuso; sem cartão fica **restricted mode** | Sim | 1 GB | Limitado | — | Restrito em restricted | [offers](https://www.alwaysdata.com/en/offers/), [restricted](https://help.alwaysdata.com/en/docs/admin-billing/profile/restricted-mode/) |
| — | PythonAnywhere Free | Não | Sim (`*.pythonanywhere.com`) | 512 MiB | **Não** (contas novas sem scheduled tasks desde 2026-01) | Web app expira 1 mês | **Whitelist** de outbound → scanners quase inviáveis | [FreeAccountsFeatures](https://help.pythonanywhere.com/pages/FreeAccountsFeatures/), [whitelist](https://www.pythonanywhere.com/whitelist/) |
| ✗ | Hugging Face Spaces Docker | Conta free **já não cria** Docker/CPU Basic (precisa PRO) | — | Ephemeral; buckets pagos | — | Sleep | — | [Spaces overview](https://huggingface.co/docs/hub/en/spaces-overview) |
| ✗ | Fly.io | Trial sem cartão (2 h VM / 7 dias); depois **cartão obrigatório** | — | — | — | — | — | [pricing](https://docs.fly.io/about/pricing), [trial](https://docs.fly.io/about/free-trial) |
| ✗ | Koyeb | **Cartão** ($29 hold) | — | Free sem volumes | Free ≠ Worker | Sleep 1 h | — | [pricing FAQ](https://www.koyeb.com/docs/faqs/pricing) |
| ✗ | Northflank Sandbox | **Cartão** para criar recursos | — | — | — | — | — | [add a card](https://northflank.com/docs/v1/application/billing/add-a-card) |
| ✗ | Cloudflare Workers | Sem cartão no free | Sim | Sem disco de processo Python | Não é daemon Python | — | Limites de CPU | inadequado ao Control |
| ✗ | Oracle / GCP Always Free | Cartão p/ verificação | — | — | — | — | — | rejeitado pelo owner |

### Adaptações no projeto (já feitas)
- Processo único: `cyberswarm control serve` **com workers em threads** (não use `--no-workers` nestes hosts).
- Env: `PORT`, `CONTROL_DATA`/`CYBERSWARM_DATA`, `CONTROL_HOST`, `CONTROL_SECURE_COOKIE`, `CONTROL_ALLOW_LAN`, `CONTROL_PASSWORD`.
- Keep-alive público: `GET /api/ping` → `{"ok":true,…}` (sem dados sensíveis).
- `Dockerfile` + `deploy/render/entrypoint.sh` (init owner opcional + serve).
- `deploy/serv00/*` scripts SSH.

---

## Escolha nº 1 — Serv00 (recomendado)

**Conta do owner:** e-mail no [serv00.com](https://www.serv00.com/) (sem cartão).  
**URL:** `https://LOGIN.serv00.net` (ou domínio próprio) via proxy Nginx → `127.0.0.1:PORTA`.  
**Limites:** 3 GB disco, 512 MB RAM, 15 processos, 3 portas TCP; fórum-only support; EU. Processo em `nohup`/`screen` sobrevive; site tipo Passenger dormiria 24 h — **não usamos Passenger**, usamos **proxy + daemon**.

### Passos manuais do owner
1. Registar em serv00.com (aguardar e-mail de ativação — fila possível).
2. Entrar no DevilWEB; ativar **Binexec** (software próprio).
3. **Port reservation** → reservar 1 porta TCP; anotar o número.
4. SSH: `ssh LOGIN@sN.serv00.com` (host no e-mail/painel).

### O que um agente pode fazer **depois** do login SSH / painel
1. `git clone` ou `scp` do projeto para `~/cyberswarm`.
2. `echo PORTA > ~/cs-port.txt`.
3. `CONTROL_PASSWORD='…' ./deploy/serv00/bootstrap.sh`.
4. `./deploy/serv00/run-detached.sh` (ou `screen -dm bash deploy/serv00/start.sh`).
5. `devil www add LOGIN.serv00.net proxy localhost PORTA` + `devil www options LOGIN.serv00.net sslonly on` + emitir Let’s Encrypt no painel.
6. Verificar: `curl -s https://LOGIN.serv00.net/api/ping` e abrir PWA no A32.
7. Instalar crontab de vigilância (`deploy/serv00/cron.keepalive.example`).

**Não fazer:** expor portas admin/shell; correr labs ofensivos contra alvos fora de 127.0.0.1 sem autorização.

---

## Escolha nº 2 — Render Free (mais simples, pior persistência)

**Conta do owner:** GitHub / Google / e-mail no [render.com](https://render.com) — docs oficiais: free **sem pagamento** para Web Service.  
**URL:** `https://NOME.onrender.com`.  
**Limites críticos:**
- Sleep **15 min** sem tráfego inbound → cold start ~1 min; FS **apagado** no sleep/redeploy → **fila SQLite some**.
- 512 MB RAM / 0.1 CPU; 750 instance-hours/mês; sem persistent disk no free.
- Sem payment method: excesso de bandwidth/build **suspende** em vez de cobrar.
- Alto volume de tráfego **iniciado pelo serviço** (ex. scans massivos) pode suspender o free.

Mitigações: keep-alive externo a cada ≤10 min em `/api/ping` (cron-job.org / UptimeRobot free, **sem cartão**); aceitar perda de histórico OU exportar backups periódicos para GitHub gist/Drive do owner.

### Passos manuais do owner
1. Criar conta Render **sem** adicionar cartão.
2. Publicar repo GitHub com este código (ou fork).
3. Dashboard → **New → Blueprint** (ficheiros `deploy/render/render.yaml` + `Dockerfile` na raiz) **ou** New Web Service → Docker → Free.
4. Env vars: `CONTROL_PASSWORD` (segredo), `CONTROL_USER=dono`.
5. Deploy → abrir URL → login.

### O que um agente logado no dashboard Render pode fazer
1. Ligar o repositório GitHub do owner.
2. Criar Web Service free, runtime Docker, health check `/api/ping`.
3. Preencher env (password via secret UI — owner cola a senha).
4. Disparar deploy; ler logs; testar `/api/ping`, `/manifest.json`, login.
5. Configurar keep-alive externo apontando a `/api/ping`.

---

## Menção: GitHub Codespaces (demo / curto prazo)

Útil se o owner já tem GitHub pessoal: 120 core-h/mês free, sem cartão até esgotar.  
`devcontainer` + forward porta **public**. Não substitui hosting 24/7 (quota e idle stop). Bom para validar PWA no A32 durante algumas horas.

---

## Checklist A32 após HTTPS
1. Chrome → URL HTTPS → login owner.  
2. ⋮ → Adicionar à tela inicial.  
3. Chat → criar missão lab → ver Tarefas; pause/cancel.  
4. Desligar dados móveis → banner offline → Tentar de novo.

## Custos
**R$ 0 / USD 0** se permanecer no free e **não** adicionar cartão.  
Conta necessária: **e-mail (Serv00)** ou **GitHub (Render/Codespaces)**.
