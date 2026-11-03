# Hospedagem gratuita — CyberSwarm Control 2.0

Medido neste box em 2026-11-03 (America/Sao_Paulo), **sem carga de scan**:

| Processo | RSS aproximado |
|---|---|
| `cyberswarm control serve` | ~46–60 MB |
| `cyberswarm worker` (idle) | ~80–100 MB |
| **Soma idle** | **~130–160 MB** |
| Disco projeto + zip | ~2–5 MB código; labs/ferramentas sobem para GB se instalados |
| Pico sob lab Juice/VAmPI | +nuclei/OSV pode passar de **512 MB–1.5 GB** RSS temporário |

Requisitos mínimos recomendados para operação telefónica contínua: **1 vCPU, 1 GB RAM, 10 GB disco, processo persistente (sem sleep), HTTPS**.

## Comparativo free tiers ([não testado] salvo onde indicado)

| Provedor | Conta/cartão | Sleep | Disco persistente | Worker background | Nota |
|---|---|---|---|---|---|
| **Oracle Always Free** (VM Ampere/x86) | Conta Oracle; cartão às vezes pedido p/ verificação, sem cobrança se ficar no free | Não (VM 24/7) | Sim (boot volume) | Sim | **Recomendado** se a conta free for aprovada |
| **GCP e2-micro** (free tier) | Conta Google; cartão costuma ser exigido | Não | Sim | Sim | Bom fallback; cuidado com cota regional |
| **Fly.io** | Conta; cartão pode ser pedido | Machines podem parar sem tráfego no free | Volume pago/limitado | Possível com care | [não testado] |
| **Render** free web | Conta | **Sim** (~15 min) — **rompe a fila** | Efêmero no free | Não confiável | Evitar para workers |
| **Koyeb** free | Conta | Pode hibernar | Limitado | Limitado | [não testado] |
| **Railway** trial | Conta; crédito esgota → para | Não no trial | Sim no trial | Sim no trial | Não é forever-free |
| **HF Spaces** | Conta HF (grátis) | Sleep em Spaces CPU free | Efêmero | Inadequado p/ fila longa | Só demo |
| **PythonAnywhere** free | Conta | Sem always-on worker | Limitado | **Não** (sem processos longos no free) | Inadequado |
| **Este box + túnel** | — | Box pode hibernar | Sim no workspace | Sim | **Túnel público bloqueado** (ver abaixo) |

## Recomendação

1. **Principal:** Oracle Cloud Always Free (VM) + `docker compose` / `install.sh` + TLS (Let’s Encrypt ou Cloudflare Tunnel **nomeado** com conta free CF).
2. **Fallback sem nuvem:** PC/home ou Android antigo com **Termux** rodando `cyberswarm control serve --tls` + `cyberswarm worker`, e um túnel (`cloudflared` quick ou Pinggy SSH) — URL efêmera, uptime = aparelho ligado.
3. **Evitar:** Render/PythonAnywhere free para produção (sleep / sem worker).

## Túneis sem conta a partir **deste** box (testados 2026-11-03)

| Método | Resultado |
|---|---|
| cloudflared quick (QUIC) | URL emitida; edge **QUIC :7844 FAIL** |
| cloudflared `--protocol http2` | URL emitida; **TLS handshake EOF** com edge |
| localtunnel (`loca.lt`) | URL emitida; público **502/503 Tunnel Unavailable** (WebFetch externo confirmou) |
| tunnelmole | **ECONNRESET** no serviço |
| bore.pub | **timeout** waiting for initial message |
| localhost.run / serveo / pinggy (SSH) | **sem `ssh` no PATH**; Paramiko: **EOF no banner SSH** (porta 22/443 SSH filtrada) |
| playit.gg agent | binário ok; precisa claim/IPC — não usável sem setup de conta |

**Conclusão:** este ambiente de sandbox **não permite túnel reverso público**. Rode o supervisor em `scripts/tunnel-supervisor.sh` num PC com saída livre.

Custo desta entrega: **R$ 0 / USD 0**. Contas free (Oracle/GCP/HF) exigem **ação do proprietário**.

## Atualização sem cartão (2026-11-03 ~20:30 -03)

Oracle/GCP rejeitados (cartão). Ver ranking completo e passos: **`docs/IMPLANTACAO_SEM_CARTAO.md`**.

| Rank | Opção | Cartão | Persistência SQLite | Sleep |
|---|---|---|---|---|
| **1** | Serv00 | Não | Sim (3 GB) | Daemon próprio não dorme |
| **2** | Render Free | Não | Não (efémero) | 15 min |
| — | HF Spaces Docker | Precisa PRO p/ criar | Ephemeral | — |
| — | Fly/Koyeb/Northflank | Cartão | — | — |

Configs prontas: `deploy/serv00/`, `deploy/render/`.
