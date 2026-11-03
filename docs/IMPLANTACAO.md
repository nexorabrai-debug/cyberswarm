# Implantação gratuita — CyberSwarm Control

O celular é o **controle remoto**; o processamento fica num servidor/PC. Tudo abaixo é gratuito; o que não rodamos aqui está marcado **[não testado]**.

## 1. No próprio PC / notebook (testado no box)
```bash
pip install -e .
cyberswarm control init --data ~/cs-control
CONTROL_PASSWORD='…' cyberswarm control adduser --data ~/cs-control --user dono --role owner
# terminal 1 — API/PWA
cyberswarm control serve --data ~/cs-control --tls --port 8770
# terminal 2 — worker (sobrevive se fechar o browser)
cyberswarm worker --data ~/cs-control
```
Acesse `https://127.0.0.1:8770/` (aceite o aviso do certificado autoassinado).

## 2. Túnel SSH a partir do celular
No PC: `serve` em 127.0.0.1. No celular (Termux/ConnectBot):
`ssh -L 8770:127.0.0.1:8770 usuario@seu-pc` e abra `http://127.0.0.1:8770`.

## 3. Cloudflare Tunnel (quick tunnel, sem conta) — [parcial]
```bash
cloudflared tunnel --url http://127.0.0.1:8770
```
Use `cyberswarm control serve … --secure-cookie` (ou `--tls` atrás do túnel HTTP local).
Quick tunnels são temporários e públicos: **senha forte obrigatória**. Ver OWNER_CREDENTIALS.txt se levantado neste box.

## 4. Oracle Cloud Free Tier — [não testado]
VM Ampere/AMD always-free, Ubuntu. Abrir só porta 443. Instalar Python 3.11+, clonar o zip, `install.sh`, `serve --tls --host 0.0.0.0 --allow-lan` atrás de firewall restrito ao seu IP, ou melhor: só 127.0.0.1 + cloudflared.

## 5. Google Cloud e2-micro free — [não testado]
Mesmo esquema; atenção ao limite de transferência.

## 6. Docker (se disponível) — [não testado neste box: sem Docker]
Ver `Dockerfile` e `docker-compose.yml` na raiz do projeto.

## install.sh
Script em `scripts/install.sh`: cria venv, instala o pacote, opcionalmente busca ferramentas OSS (`fetch_labs.sh`).


## Túnel rápido cloudflared a partir do box de CI

Tentativa em 2026-11-03: binário `cloudflared` 2026.8.2 baixado e `tunnel --url http://127.0.0.1:8770` iniciado.
**Bloqueio**: egress do sandbox impede QUIC/TCP na porta 7844 (e HTTP/2 no edge falha com TLS EOF). API Cloudflare responde, mas o conector não estabelece.
**Alternativa**: rodar o mesmo comando num PC/home com saída livre; Control local em `127.0.0.1:8770` + `--secure-cookie`.
