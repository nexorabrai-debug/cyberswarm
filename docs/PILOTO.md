# Piloto com cliente real (Hacker AI 1.1)

> Modelo operacional. **Não é parecer jurídico.** Antes do primeiro piloto, peça para um advogado revisar o termo.

## 1. Termo de autorização (modelo)
```
TERMO DE AUTORIZAÇÃO PARA AVALIAÇÃO DE SEGURANÇA DEFENSIVA — Nº TERMO-AAAA-NNN

Contratante: [razão social], CNPJ [..], representada por [nome, cargo], que declara ter poderes
para autorizar testes nos ativos abaixo e ser titular ou ter autorização do titular de cada um.

1. Ativos autorizados (somente estes): [domínios/IPs/apps — ver Formulário de Escopo anexo].
2. Período: de [data/hora] a [data/hora] (fuso America/Sao_Paulo).
3. Tipo de teste: verificação NÃO destrutiva (requisições de leitura, limite de [5] req/s,
   sem exploração, sem força bruta, sem negação de serviço, sem acesso a dados pessoais
   além do mínimo necessário para provar a exposição; dados encontrados são mascarados).
4. Ferramentas: CyberSwarm [versão]; [nuclei com tags: ... | não usar nuclei]; [MobSF para APK fornecido].
5. Contato de emergência do contratante: [nome, telefone]. Interrupção imediata a pedido.
6. Confidencialidade e LGPD: resultados entregues só ao contratante; evidências apagadas em [30] dias.
7. Terceiros (hospedagem, CDN, SaaS): o contratante confirma que os termos desses provedores permitem o teste.

Local, data. Assinaturas: Contratante / Responsável técnico.
```

## 2. Formulário de escopo
| Campo | Exemplo |
|---|---|
| Hosts/domínios | `www.padaria-exemplo.com.br` |
| Fora do escopo (explícito) | `pagamentos.exemplo.com` (gateway de terceiro) |
| Ambiente | produção / homologação |
| Janela de teste | 2026-11-10 22:00–23:59 |
| Limite de taxa | 5 req/s, 300 req por análise |
| Ferramentas externas | nuclei: sim/não · MobSF: APK enviado pelo cliente |
| Contato de emergência | nome + telefone |
| Nº do termo | TERMO-2026-001 |

## 3. Processo
1. Reunião inicial → termo assinado e formulário de escopo preenchido.
2. Cadastre o cliente em `clients.json` (o fluxo está abaixo). Não coloque senhas nem tokens nesse arquivo, porque o programa recusa.
3. `cyberswarm clients-check` precisa mostrar o cliente válido e o escopo correto.
4. Faça antes um ensaio no laboratório local (`cyberswarm hacker validate --lab vampi`) para conferir as ferramentas.
5. Rode dentro da janela combinada, por exemplo: `cyberswarm scan --client padaria-exemplo --target https://www.padaria-exemplo.com.br --agents web,tls`.
6. Revise o relatório. Os itens marcados como `suspeita` **não** vão como vulnerabilidade: vão como "a verificar" ou são retirados.
7. Entregue o PDF e marque uma reunião de explicação. Depois da correção, rode de novo e compare (`compare`).
8. Rode `cyberswarm audit-verify`, arquive o audit.log e apague as evidências no prazo do termo.

## 4. Fluxo do clients.json (exemplo)
```
cp clients.example.json clients.json
# edite: id, name, authorization_ref=TERMO-2026-001, authorized_by, valid_from/valid_until, scope.hosts
cyberswarm clients-check
cyberswarm scan --client padaria-exemplo --target https://www.padaria-exemplo.com.br --agents web,tls
# host fora do escopo ou termo vencido -> BLOQUEADO (registrado no audit.log)
```

## 5. Preço do piloto — **[não verificado]**
Os valores abaixo são hipóteses e não vêm de pesquisa de mercado: piloto gratuito ou simbólico para 3 a 5 pequenos negócios; depois, R$ 300 a 900 por avaliação de um site, mais a reavaliação. **[não verificado]**. Valide os preços com clientes reais antes de divulgar.

## 6. O que NÃO prometer
- Não prometer "100% de cobertura" nem "site seguro". Na validação externa, a revocação foi baixa em vários laboratórios (veja `VALIDACAO_EXTERNA.md`).
- Não prometer teste de invasão (pentest). O CyberSwarm não faz exploração ativa.
