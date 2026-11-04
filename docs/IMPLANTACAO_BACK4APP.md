# CyberSwarm no Back4App (plano grátis)

**Endereço:** https://cyberswarmcontrol-wnfaas65.back4.app
**Custo:** US$ 0, sem cartão. O plano pago (US$ 5/mês) **não** foi contratado.

## Instalar no Galaxy A32
1. Abra o endereço no **Chrome**.
2. Entre com o usuário `dono` e a senha (fica em `OWNER_CREDENTIALS.txt`, fora do GitHub).
3. Toque em **⋮** (três pontinhos) e depois em **Adicionar à tela inicial**.
4. Abra pelo ícone "CyberSwarm" na tela inicial.

## Testes remotos (3/11/2026, ~21h, horário de Brasília)
| Teste | Resultado |
|---|---|
| Login de dono por HTTPS (cookie + CSRF) | OK |
| `/api/ping` público (keep-alive) | OK |
| Chat Hacker AI ("auditar laboratório completo") cria tarefa real no lab embutido | OK (12 tarefas, 11 módulos) |
| Worker roda dentro do mesmo processo (threads) e termina a tarefa | OK (~20 s, 80 achados) |
| Lista de achados `/api/jobs/N/findings` | OK (80 itens, segredos mascarados) |
| Cancelar tarefa | OK (status "cancelada") |
| Chat "status" mostra a fila | OK |
| Pausar tarefa **na fila** | OK (aceita) |
| Pausar tarefa **já executando** | **FALHA**: aceita a pausa, mas a execução continua e termina como "concluída"; depois "retomar" dá "não está pausada" |

Só foi usado o laboratório embutido. Nenhum alvo de terceiros.

## Limites do plano grátis
- **O endereço grátis expira ~60 minutos depois de cada publicação** (documentado pela Back4App). Não é "dormir por falta de uso": ping de keep-alive (UptimeRobot/cron-job.org) **não** resolve isso.
- Para voltar: no painel Back4App, *Actions → Deploy the latest commit*, ou enviar um commit novo ao GitHub (auto-deploy ligado).
- 256 MB de RAM, 0,25 CPU.
- Sem disco permanente: a cada publicação o banco SQLite (histórico, tarefas) recomeça.

## Plano B
1. **Render grátis** (dorme após 15 min, acorda com ping): pede autorização temporária de **US$ 1 no cartão**. Só com o "sim" do Renato.
2. **Serv00** (grátis, só e-mail): precisa de SSH, que o computador do bot não alcança. Renato pode fazer pelo celular (Termux).
3. **Modo local na rede Wi-Fi**: `cyberswarm control serve --allow-lan --tls` num PC/notebook e abrir pelo IP no A32.
4. **Back4App pago** (US$ 5/mês): endereço fixo. Só com autorização.
