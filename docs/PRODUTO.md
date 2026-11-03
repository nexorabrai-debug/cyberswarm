# CyberSwarm Website Security Audit

> Tudo marcado **[não verificado]** é estimativa minha, sem pesquisa de mercado nesta entrega. Confira antes de usar com cliente.

## O que o cliente recebe
1. Análise automática e passiva do site:
   - cabeçalhos de segurança;
   - cookies;
   - HTTPS, TLS e certificado (versões aceitas, validade, autoassinado, nome, HSTS);
   - CORS;
   - métodos HTTP;
   - arquivos expostos (`.env`, `.git`, backup).
2. Classificação de risco (Crítico, Alto, Médio, Baixo, Informativo), seguindo uma tabela fixa (`docs/SEVERIDADE.md`).
3. Evidências técnicas que dá pra reproduzir: comando `curl`/`openssl`, requisição e resposta. Os segredos aparecem mascarados.
4. Explicação de cada falha em português simples: o que é, qual o risco e como corrigir.
5. Separação entre **Confirmado** e **Suspeita**.
6. **Relatório profissional em PDF** e versão HTML para celular.
7. **Reteste**: comparação depois da correção (`cyberswarm compare`), mostrando o que foi CORRIGIDO e o que PERSISTE.

Gerar a demonstração (só no laboratório próprio): `cyberswarm demo-comercial`

## Pacotes e preços sugeridos [não verificado]
| Pacote | Inclui | Preço sugerido |
|---|---|---|
| **Básico** | 1 domínio, relatório PDF, 1 reteste em até 30 dias | R$ 197 [não verificado] |
| **Profissional** | Até 3 domínios + API (se o cliente fornecer o OpenAPI), call/áudio de 20 min explicando, 2 retestes | R$ 497 [não verificado] |
| **Mensal** | Reanálise todo mês + comparação + alerta de certificado vencendo | R$ 97/mês [não verificado] |

Como referência, serviços parecidos aparecem em plataformas de freelancer em faixas bem diferentes [não verificado]. Também existem ferramentas grátis que fazem parte disso: Mozilla Observatory, securityheaders.com, SSL Labs. **O valor vendido é a explicação em português, a priorização e o reteste**, não a ferramenta.

## Termo de autorização (modelo)
> Modelo simples. **Não é aconselhamento jurídico**; se possível, revise com um advogado.

```
TERMO DE AUTORIZAÇÃO PARA AVALIAÇÃO DE SEGURANÇA

Nº do termo: TERMO-AAAA-NNN

CONTRATANTE: [Razão social], CNPJ [__], representada por [nome], [cargo], CPF [__],
que declara ter poderes para autorizar testes nos sistemas abaixo.

PRESTADOR: [Nome], CPF [__], e-mail [__].

1. ESCOPO AUTORIZADO (somente):
   - Domínios: [www.exemplo.com.br]
   - Fora do escopo: qualquer outro domínio, IP, sistema de terceiros (hospedagem, gateways de pagamento, e-mail).

2. PERÍODO: de [dd/mm/aaaa] a [dd/mm/aaaa], em horário [__].

3. TIPO DE TESTE: verificação automatizada e PASSIVA (requisições GET/HEAD/OPTIONS e conexão TLS),
   com limite de até 5 requisições por segundo. NÃO inclui: invasão, força bruta, negação de serviço,
   engenharia social, alteração ou exclusão de dados, acesso a dados de clientes.

4. CONFIDENCIALIDADE: os resultados serão entregues somente ao CONTRATANTE e não serão divulgados.
   Evidências com dados sensíveis serão mascaradas e apagadas em até [30] dias após a entrega.

5. CONTATO DE EMERGÊNCIA: [nome/telefone]. O PRESTADOR interrompe os testes imediatamente se solicitado.

6. O CONTRATANTE declara que é dono dos sistemas listados ou tem autorização do dono.

[Cidade], [data]

_____________________________          _____________________________
CONTRATANTE                             PRESTADOR
```
Depois de assinado, cadastre o termo em `clients.json`: o `authorization_ref` recebe o número do termo, e as datas e o escopo precisam ser os mesmos do termo.

## Plano de primeiro faturamento
1. **Portfólio (hoje):** usar `cyberswarm-demo.pdf` (laboratório) como exemplo do relatório.
2. **3 auditorias grátis ou simbólicas** para negócios conhecidos (amigos, comércio local), **sempre com o termo assinado**, em troca de depoimento e permissão para citar o nome.
3. **Anúncio** do serviço "Relatório de segurança do seu site em 48h" no 99Freelas, Workana, Fiverr e grupos locais de empreendedores. Tudo isso precisa de conta e ação do dono; nada foi publicado.
4. **Proposta curta** por mensagem: o problema ("seu site pode estar mostrando arquivos internos"), o que entrega (o PDF), o preço do pacote Básico e o termo.
5. **Converter em mensal** quem corrigir e quiser acompanhamento.
6. **Meta [não verificado]:** 1 a 3 vendas do Básico no primeiro mês.

## Riscos e cuidados
- Nunca rodar contra domínio sem termo assinado; o programa bloqueia, mas a responsabilidade é sua.
- Não prometer "site 100% seguro".
- Guardar os termos assinados fora do `clients.json`, em uma pasta segura.
