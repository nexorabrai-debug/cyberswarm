# CyberSwarm 2.0 no Galaxy A32 (Termux) — grátis, sem cartão

Tudo roda **no seu próprio celular**. Não tem link que vence e não custa nada.

> **Versão liberada:** tag `v2.0.0` = commit `02c6cdfdbe8f7440703a5265e4aacc417dacee35`.
> **Status:** testado num Termux ARM64 **emulado** (oficial `termux/termux-docker:aarch64` rodando com qemu + proot num computador).
> **Ainda NÃO testado num Galaxy A32 de verdade.** Veja "O que ainda depende do teste no celular".

## Passo a passo

1. **Instale o Termux pelo GitHub** (NÃO use a Play Store, a versão de lá é velha):
   https://github.com/termux/termux-app/releases → baixe `termux-app_..._github-debug_arm64-v8a.apk` e instale.
2. Abra o Termux, cole **este comando (uma linha só)** e aperte Enter:
   ```
   curl -fsSL https://raw.githubusercontent.com/nexorabrai-debug/cyberswarm/02c6cdfdbe8f7440703a5265e4aacc417dacee35/termux/instalar.sh | bash -s 02c6cdfdbe8f7440703a5265e4aacc417dacee35
   ```
   Se perguntar algo (Y/n), aperte Enter. Demora (no emulador levou ~8 min; no celular deve ser menos, depende da internet).
3. Quando pedir a **senha do usuário `dono`**, digite uma com 10+ caracteres ou aperte Enter para gerar uma. Se gerar, **anote**: aparece só uma vez. Fica guardada só no celular, em `~/.cyberswarm_env`.
4. Ligar: `bash ~/iniciar.sh` (deixe o Termux aberto).
5. Chrome → **http://127.0.0.1:8770** → usuário **dono** + sua senha.
6. Menu **⋮** → **Adicionar à tela inicial** → **Instalar**.

Para desligar: **Ctrl + C** no Termux. Para atualizar no futuro: rode o comando novo que eu mandar (senha e dados são mantidos).

## Como a versão fica fixa (sem baixar código variável da main)
- O comando baixa o `instalar.sh` **do commit exato** (`.../cyberswarm/02c6cdfdbe8f7440703a5265e4aacc417dacee35/termux/instalar.sh`), não da `main`.
- O mesmo SHA é passado ao instalador (`bash -s 02c6cdfdbe8f7440703a5265e4aacc417dacee35`). Ele faz `git fetch` **desse commit** e confere `git rev-parse HEAD`. Se for diferente, **para** com erro.
- Por que o SHA não está dentro do instalador: um arquivo não consegue conter o SHA do próprio commit. Por isso o SHA vai no comando, e a documentação (este arquivo) foi escrita num commit **posterior**, que muda só documentos. O código liberado é exatamente o da tag `v2.0.0`.
- Sem SHA no comando, o instalador usa a tag `v2.0.0` e mostra o commit.
- Pacotes do Termux (`pkg`) e o `fpdf2` (pip, versão `>=2.7,<3`) vêm dos repositórios oficiais e não são fixos por versão.

## Dependências (instaladas pelo instalador)
| Pacote | Para quê |
|---|---|
| `python` (3.10+; no teste veio 3.14) | tudo; já inclui `ssl`, `sqlite3`, `http.server`, `asyncio` |
| `openssl`, `ca-certificates` | TLS (verificação de sites https) |
| `openssl-tool` | comando `openssl`, usado só como alternativa para criar certificado local |
| `libsqlite` | banco SQLite (no teste: SQLite 3.54.1, OpenSSL 3.6.5) |
| `git` | baixar a versão fixa |
| `python-cryptography` | detalhes do certificado TLS e cifragem da chave de IA |
| `python-pillow` + pip `fpdf2` | relatório PDF |

Observação: o `python-pip` do Termux traz o `clang` junto (recomendado). Isso deixa a instalação grande (~870 MB no total), mas é o que permite instalar o `cryptography` sem erro.

**O que piora se faltar algo opcional:**
- sem `fpdf2`: o PDF vira HTML (abra no Chrome e use Imprimir → Salvar como PDF);
- sem `cryptography`: o TLS ainda vê versões e HSTS, mas não lê validade/nome do certificado; chave de API de IA não é salva cifrada (não é salva);
- sem `nmap`, `nuclei`, `semgrep`, `trivy`, `sslyze`, `bandit`: esses módulos são **pulados** (não vêm no Termux por padrão). O `nmap` dá para instalar com `pkg install nmap` (não testado).
- O `termux-wake-lock` só funciona com o app Termux de verdade (no emulador não existe).

## Backup e restauração
- **Fazer backup** (pode ser com o CyberSwarm ligado):
  `bash ~/cyberswarm-backup.sh`
  Salva em `~/cyberswarm-backups/cyberswarm-DATA.tar.gz`, **com** a senha/chave (`~/.cyberswarm_env`). Os bancos são copiados com a função de backup do SQLite e conferidos (`integrity_check`).
- **Backup para a pasta do celular** (para copiar para o PC/Drive):
  `bash ~/cyberswarm-backup.sh --compartilhar`
  Pede permissão de armazenamento (`termux-setup-storage`) e salva em `Armazenamento interno/CyberSwarm-backups`, **sem** a senha/chave (outros apps conseguem ler essa pasta).
- **Restaurar:** desligue (Ctrl+C) e rode `bash ~/cyberswarm-restore.sh ~/cyberswarm-backups/ARQUIVO.tar.gz`.
  Os dados atuais não são apagados: viram `~/cyberswarm-data.antes-restore-DATA`.
  Depois do restore, a senha que vale é a **da época do backup**. Se o backup for "--compartilhar" (sem chave), a chave de IA salva precisa ser cadastrada de novo.

## Consumo (medido)
| Item | Emulador ARM64 (qemu) | Nativo x86 (referência) |
|---|---|---|
| RAM parado | 250 MB* | 27 MB |
| RAM pico numa missão de laboratório | 281 MB* | 98 MB |
| Tempo de uma missão de laboratório (12 tarefas, 83 achados) | 32–38 s | 12 s |
| CPU do servidor por missão | 25,9 s* | 1,9 s |

\* No emulador os números incluem o próprio emulador (qemu), então são **maiores** que no celular. A estimativa realista para o A32 fica entre as duas colunas: **~30–100 MB de RAM** (o A32 tem 4 GB).

Armazenamento: código ~4 MB; dados ~1 MB por missão (4 missões = 4,3 MB); backup de 4 missões = 552 KB; pacotes do Termux ~870 MB (clang/llvm ~430 MB, python 26 MB, git 25 MB).

**Bateria: só estimativa, não medida.** Parado, o servidor quase não usa CPU, mas o wake lock impede o celular de dormir; deixar ligado o dia todo deve gastar bateria visivelmente. Cada missão de laboratório usa alguns segundos de CPU. Recomendação: ligue só quando for usar e desligue com Ctrl+C. O número real depende do teste no A32.

## Dica de bateria (importante)
O Android fecha apps em segundo plano. Para não parar:
- Configurações → Aplicativos → Termux → Bateria → **Sem restrições**.
- O `iniciar.sh` já ativa o "wake lock" do Termux (aparece na notificação do Termux).
  Se quiser soltar: puxe a notificação do Termux → **Release wakelock**.

## Segurança: só 127.0.0.1
- `iniciar.sh` usa `--host 127.0.0.1` fixo e apaga `CONTROL_ALLOW_LAN`/`HOST` antes de ligar.
- O servidor recusa qualquer endereço fora de 127.0.0.1 sem `--allow-lan` (`control/server.py`, função `serve`).
- Testado: mesmo com `CONTROL_ALLOW_LAN=1` e `HOST=0.0.0.0` no ambiente, continuou só em `127.0.0.1:8770`; pedido pelo IP de rede do computador foi recusado.
- Não há terminal nem execução de comandos pela interface. A senha não fica no frontend.

## Limites (verdade)
- Só funciona **enquanto o Termux estiver ligado**. Fechou o Termux = parou.
- Só abre **no próprio celular**.
- Ferramentas externas não vêm instaladas; os módulos que dependem delas são pulados.
- Testes ofensivos só em laboratórios próprios ou alvos com autorização por escrito.
- Apagou o Termux = perdeu os dados (faça backup `--compartilhar` e copie o arquivo para fora).

## Relatório de testes (04/11/2026, horário de Brasília)
Ambiente: imagem oficial `termux/termux-docker:aarch64` (Android 9 libs + bootstrap Termux), rodando com `qemu-aarch64-static` 7.2 + `proot` 5.3 num computador x86_64 (sem Docker). `uname -m` = `aarch64`.

| Teste | Resultado |
|---|---|
| Instalação limpa com o comando de uma linha (SHA fixo) | ✅ passou (~8 min); commit conferido |
| `ssl`, `sqlite3`, `cryptography`, `fpdf` importam | ✅ |
| Atualização por cima (senha mantida, sem pedir de novo) | ✅ |
| SHA errado/inexistente | ✅ o `git fetch` falha e o instalador para |
| `iniciar.sh` liga e cria o usuário dono | ✅ |
| Login, página inicial, `manifest.json`, `sw.js` (PWA) | ✅ HTTP 200 |
| Chat "auditar laboratório completo" cria missão de 12 tarefas | ✅ 83 achados, PDF/HTML/MD/JSON gerados |
| Pausar → continua pausada → retomar → conclui | ✅ |
| Cancelar | ✅ |
| Só 127.0.0.1 (ss) e IP de rede recusado, mesmo com ALLOW_LAN=1 | ✅ |
| Backup com servidor ligado + restauração depois de apagar os dados | ✅ 4 missões voltaram e o login funcionou |
| Suíte de testes (Python nativo) | ✅ 165 passaram, 1 pulado |

### O que ainda depende do teste no Galaxy A32 de verdade
- Instalar o APK do Termux e o `pkg` com a internet do celular (tempo e espaço reais).
- Chrome do Android abrindo `127.0.0.1:8770` e o **"Adicionar à tela inicial"/instalar PWA**.
- `termux-wake-lock` e o Android fechando o Termux em segundo plano (economia de bateria da Samsung).
- `termux-setup-storage` e o backup `--compartilhar` (no emulador não existe armazenamento compartilhado).
- RAM, tempo e **bateria reais** no processador do A32.

## Se der problema
- "command not found: curl": `pkg install curl` e repita o passo 2.
- Página não abre: confira se o Termux mostra "CyberSwarm rodando".
- Esqueceu a senha: restaure um backup feito com a senha conhecida, ou `rm ~/.cyberswarm_env ~/cyberswarm-data/control.db` e repita o passo 2 (apaga os usuários).
