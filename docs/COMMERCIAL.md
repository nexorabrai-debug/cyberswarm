# CyberSwarm — Plano comercial

> v0.3: o produto pronto para venda está em **docs/PRODUTO.md** (pacotes, termo de autorização, plano de faturamento). Este arquivo fica como mapa geral.

> Itens marcados **[não verificado]** são estimativas ou informação que não conferi nesta entrega. Confira antes de usar com cliente.

## Serviços que dá pra vender
1. **Relatório de segurança de site para pequenas empresas (PMEs)**: rodar o agente web (com autorização assinada), entregar relatório em português com o que corrigir. Preço sugerido R$150–500 por site **[não verificado, estimativa]**.
2. **Revisão de configuração de nuvem (Terraform/JSON)**: para startups e devs. Análise estática, não precisa acessar a conta do cliente.
3. **Checagem de app Android antes de publicar**: revisar o AndroidManifest.
4. **Monitoramento mensal**: rodar de novo todo mês e mostrar o que mudou (precisa da fase 3).

Sempre: contrato/termo de autorização assinado com o dono do sistema, listando domínios e datas.

## Programas de recompensa legítimos (bug bounty)
| Plataforma | Observação |
|---|---|
| HackerOne | maior do mundo; programas com escopo publicado. Pagamento e KYC **[não verificado para RG/CPF sem passaporte]** |
| Bugcrowd | parecido; tem programas públicos e VDP |
| Intigriti | europeia; requisitos de KYC **[não verificado]** |
| BugHunt | brasileira; já existe conta `nexorahunter` (login travou antes) |
| YesWeHack | conta criada, mas KYC pede passaporte (bloqueado) |

Regra: só testar o que está no escopo publicado do programa e seguir as regras dele. O CyberSwarm não deve ser apontado para alvo de bounty sem adicionar o escopo exato no `scope.json`.

## Concorrência
Ferramentas grátis existentes: OWASP ZAP, Nuclei, Mozilla Observatory, securityheaders.com, Checkov/tfsec (nuvem), MobSF (mobile). O diferencial do CyberSwarm não é a técnica, é o **relatório em português simples para dono de PME** + tudo num comando só. Demanda real **[não verificado]**.

## Estratégia de primeiro faturamento
1. Gerar 1 relatório exemplo (usar o do lab) como portfólio.
2. Oferecer auditoria grátis ou barata para 3–5 negócios conhecidos, **com autorização assinada**, em troca de depoimento.
3. Anunciar o serviço no 99Freelas / Workana / Fiverr ("relatório de segurança de site").
4. Em paralelo, usar o tempo livre em programas VDP/bounty com escopo público (BugHunt) para ganhar reputação.
5. Converter os primeiros clientes em monitoramento mensal.
