# CyberSwarm no Galaxy A32 (Termux) — grátis, sem cartão

Tudo roda **no seu próprio celular**. Não tem link que vence e não custa nada.

## Passo a passo

1. **Instale o Termux pelo F-Droid/GitHub** (NÃO use a Play Store, a versão de lá é velha e quebra):
   abra no Chrome https://github.com/termux/termux-app/releases , baixe o arquivo
   `termux-app_..._github-debug_arm64-v8a.apk` da versão mais nova e instale
   (o Android vai pedir para permitir "instalar apps desconhecidos" — permita para o Chrome).
2. Abra o Termux e cole este comando (um só), depois aperte Enter:
   ```
   curl -fsSL https://raw.githubusercontent.com/nexorabrai-debug/cyberswarm/main/termux/instalar.sh | bash
   ```
   Se perguntar algo (Y/n), aperte Enter. Demora uns minutos.
3. Quando pedir a **senha do usuário `dono`**, digite uma com 10+ caracteres (não aparece na tela enquanto digita)
   ou só aperte Enter para gerar uma automática. Se gerar, **anote**: ela aparece só uma vez.
   Ela fica guardada só no celular, em `~/.cyberswarm_env`.
4. Para ligar o CyberSwarm, no Termux digite:
   ```
   bash ~/iniciar.sh
   ```
   Deixe o Termux aberto (pode ir para outro app, só não feche).
5. Abra o **Chrome** e acesse: **http://127.0.0.1:8770**
6. Entre com usuário **dono** e a sua senha.
7. Menu **⋮** do Chrome → **Adicionar à tela inicial** → **Instalar**. Pronto, vira um app com ícone.

Da próxima vez: abra o Termux, rode `bash ~/iniciar.sh` e toque no ícone do CyberSwarm.
Para atualizar: rode de novo o comando do passo 2 (a senha e os dados são mantidos).
Para desligar: no Termux aperte **Ctrl + C** (tecla CTRL da barra do Termux e depois C).

## Dica de bateria (importante)
O Android fecha apps em segundo plano. Para não parar:
- Configurações → Aplicativos → Termux → Bateria → **Sem restrições**.
- O `iniciar.sh` já ativa o "wake lock" do Termux (aparece na notificação do Termux).
  Se quiser soltar: puxe a notificação do Termux → **Release wakelock**.

## Limites (verdade)
- Só funciona **enquanto o Termux estiver ligado** no celular. Fechou o Termux = parou.
- Só abre **no próprio celular** (127.0.0.1). Não dá para acessar de outro aparelho.
- Usa bateria e um pouco de memória (o A32 aguenta, mas tarefas grandes ficam mais lentas).
- Ferramentas externas (nuclei, trivy, semgrep etc.) não vêm instaladas; os módulos que dependem delas são pulados.
- Testes ofensivos só em laboratórios próprios ou alvos com autorização por escrito.
- Se trocar de celular ou apagar o Termux, os dados (`~/cyberswarm-data`) somem.

## Se der problema
- "command not found: curl": rode `pkg install curl` e repita o passo 2.
- Página não abre: confira se o Termux mostra "CyberSwarm rodando".
- Esqueceu a senha: `rm ~/.cyberswarm_env ~/cyberswarm-data/control.db` e repita o passo 2 (apaga os usuários).
