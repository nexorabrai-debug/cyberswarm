# Manual — instalar CyberSwarm Control no Galaxy A32

O A32 (~411×914 CSS px, 1080×2400 @ ~2,625 DPR) é o **controle remoto**. O servidor roda noutro equipamento.

## 1. Subir o servidor (PC / nuvem)
Veja `IMPLANTACAO.md`. Mínimo:
```bash
cyberswarm control serve --data ~/cs-control --tls --port 8770
cyberswarm worker --data ~/cs-control
```

## 2. Abrir no Chrome do A32
1. Abra o Chrome.
2. Acesse o URL HTTPS do servidor (ou o túnel).
3. Se aparecer aviso de certificado autoassinado: **Avançado → Continuar**.
4. Faça login (usuário/senha do owner).

## 3. Instalar como aplicativo (PWA)
1. Menu ⋮ do Chrome → **Adicionar à tela inicial** (ou o botão **Instalar** no topo do app).
2. Confirme. O ícone “CyberSwarm Control” aparece na tela inicial.
3. Abra pelo ícone (abre em modo standalone, sem barra do Chrome).

## 4. Uso rápido
- **Chat**: diga «verificar TLS e API do laboratório».
- **Aprovações**: se a missão for contra cliente real, aprove/negue com justificativa.
- **Tarefas**: acompanhe progresso; Pausar / Cancelar / Retomar.
- Pode **fechar o app**: o `cyberswarm worker` continua no servidor.

## 5. Se não instalar
- Sem HTTPS (só HTTP na LAN): o Chrome **não** oferece “Adicionar à tela inicial” como PWA. Use túnel SSH ou Cloudflare Tunnel.
- Limpe dados do site se o service worker antigo travar: Chrome → cadeado → Limpar dados.


## APK / TWA (opcional — não gerado neste box)

Bloqueio medido em 2026-11-03 (America/Sao_Paulo): `java`, `javac` e `sdkmanager` ausentes; instalação gratuita do Android SDK + JDK no box não foi feita (sem pacote pré-aprovado / sem espaço/tempo garantido). Por isso **não há APK** nesta entrega.

### Caminho recomendado (PWA)
Chrome no A32 → menu → **Adicionar à tela inicial**. O manifesto (`display: standalone`) e o service worker já estão no Control.

### Bubblewrap (quando tiver JDK 17+ e Android SDK no seu PC) [não testado aqui]
```bash
npm i -g @bubblewrap/cli
bubblewrap init --manifest https://SEU_HOST/manifest.json
bubblewrap build
```
Instale o `.apk` gerado via USB (`adb install`) ou link interno. O TWA só embute a URL HTTPS do Control — o servidor continua sendo o backend.
