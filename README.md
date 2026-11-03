# CyberSwarm 1.0 (com Hacker AI)

Ferramenta de **auditoria de segurança defensiva** com vários agentes trabalhando ao mesmo tempo. Ela gera relatório em PDF e HTML (dá pra ler no celular), separa o que está **confirmado** do que é **suspeita** e compara análises para ver o que foi corrigido.

⚠️ **Só use em sistemas seus ou com autorização por escrito do dono.** Testar sistemas dos outros sem permissão é crime no Brasil (Lei 12.737/2012). O programa **bloqueia** qualquer alvo fora do laboratório que não esteja cadastrado em `clients.json` com uma autorização válida.

## 1. Instalar

Precisa de **Python 3.10 ou mais novo**. O núcleo não depende de nenhum outro pacote. Dois pacotes grátis são opcionais:
- `fpdf2`, para gerar o PDF;
- `cryptography`, para ler os detalhes do certificado TLS.

### Opção A: instalar como programa (recomendado)
```
unzip cyberswarm.zip && cd cyberswarm
pip install ".[full]"          # instala o comando `cyberswarm` com PDF e TLS
cyberswarm --help
```
Se o pip reclamar de "externally-managed-environment", use um ambiente virtual:
```
python3 -m venv ~/cs && ~/cs/bin/pip install ".[full]" && ~/cs/bin/cyberswarm --help
```

### Opção B: rodar sem instalar
```
cd cyberswarm
pip install fpdf2 cryptography      # opcional
python -m cyberswarm --help
```

### Testes (opcional)
```
pip install ".[dev]"    # ou: pip install pytest fpdf2 cryptography
python -m pytest -q
```

## 2. Demonstração

| Comando | O que faz |
|---|---|
| `cyberswarm demo` | Liga o laboratório vulnerável (HTTP 8088 e HTTPS 8443, só no seu aparelho) e roda **todos** os agentes |
| `cyberswarm demo-comercial` | Demonstração do produto "Website Security Audit": gera PDF + HTML + print do celular |

Os arquivos ficam na pasta `reports/`, na pasta onde você rodou o comando.

## 3. Ler o relatório
- `report-N-*.pdf`: o relatório para entregar ao cliente.
- `report-N-*.html`: o mesmo relatório, que abre no navegador do celular.
- `report-N-*.md` e `.json`: versões técnicas.
- Cada achado mostra a **gravidade** (Crítico, Alto, Médio, Baixo, Informativo), se é **Confirmado** (tem prova que dá pra repetir) ou **Suspeita**, o impacto, o que vimos, como corrigir e como reproduzir (comando `curl`/`openssl` ou arquivo + linha).
- As regras de gravidade estão em `docs/SEVERIDADE.md`.

## 4. Comparar antes e depois da correção
```
cyberswarm compare 1 2
```
Mostra o que é NOVO, o que foi CORRIGIDO e o que PERSISTE. Cada achado tem uma "impressão digital" própria (agente + checagem + alvo + evidência), então dois achados com o mesmo título não se confundem.

## 5. Auditar um cliente de verdade (com autorização)
1. O cliente assina o **termo de autorização** (modelo em `docs/PRODUTO.md`).
2. Copie `clients.example.json` para `clients.json` e preencha:
   - `id`, `name`, `authorization_ref` (número do termo), `authorized_by`;
   - as datas `valid_from` e `valid_until`;
   - o `scope` com os domínios autorizados.
   
   **Não coloque senhas nem tokens**: o programa recusa o arquivo.
3. Confira o cadastro: `cyberswarm clients-check`
4. Rode a auditoria:
   ```
   cyberswarm scan --client padaria-exemplo --target https://www.padaria-exemplo.com.br --agents web,tls
   ```
   Sem `--client`, com o termo vencido ou com um domínio fora do escopo, aparece **BLOQUEADO**.

Limites de segurança: o padrão é no máximo 5 requisições por segundo, 300 requisições por análise e 5 segundos de espera por resposta. Dá pra mudar com `--rate`, `--max-requests` e `--timeout`. O programa só faz GET, HEAD e OPTIONS e não segue redirecionamentos.

Trilha de auditoria: todas as operações vão para `reports/audit.log`, encadeadas por hash. Para conferir se ninguém mexeu: `cyberswarm audit-verify`.

## 6. Usar pelo celular (Android, Termux)
1. Instale o **Termux** pelo F-Droid.
2. No Termux: `pkg install python unzip` (opcional, para o PDF e o TLS: `pip install fpdf2 cryptography`; em alguns aparelhos o `cryptography` precisa de `pkg install rust` ou de `pkg install python-cryptography`).
3. `termux-setup-storage` e copie o `cyberswarm.zip` para a pasta Downloads.
4. `cd ~/storage/downloads && unzip cyberswarm.zip && cd cyberswarm && pip install .`
5. `cyberswarm demo-comercial`
6. Abra o PDF: `termux-open reports/*.pdf` (ou copie para Downloads: `cp reports/*.pdf ~/storage/downloads/`).

*O Termux não foi testado num celular de verdade nesta versão. O print de celular só sai se tiver Chrome ou Playwright; no Termux, o PDF e o HTML funcionam sem eles.*

**Sem fpdf2:** o programa tenta gerar o PDF com o Chrome em modo headless. Se não houver nenhum dos dois, ele avisa "PDF não gerado" e você abre o HTML no navegador e usa "Imprimir → Salvar como PDF".

## 7. O que ele verifica
- **web**: cabeçalhos de segurança, cookies, HTTPS, CORS, métodos perigosos (só pergunta com OPTIONS) e arquivos expostos (`.env`, `.git`, backup). Antes, compara com uma página que não existe, para evitar falso positivo.
- **tls**: versões de TLS aceitas (avisa se aceitar 1.0 ou 1.1), certificado vencido ou perto de vencer, autoassinado, nome errado e HSTS.
- **api**: lê o OpenAPI: endpoint sem login, falta de limite de requisições, erro que mostra código (também testa ao vivo no laboratório).
- **cloud**: lê Terraform/JSON/YAML: bucket S3 público, porta aberta para o mundo, segredos no arquivo.
- **code**: procura segredos no código: chaves privadas, tokens do GitHub, Slack e Google, AWS, JWT, senhas e textos de alta entropia. Ignora valores de exemplo, como `changeme` e `your_api_key`.
- **mobile** (Android): debuggable, backup, HTTP liberado, componentes exportados.
- **ios**: ATS desligado, HTTP por domínio, TLS antigo, compartilhamento de arquivos, deep links.

## 8. Limites (seja honesto com o cliente)
- As checagens são automáticas e passivas. **Não substituem um pentest manual.**
- Não há busca de CVE ao vivo; as referências são CWE/OWASP fixas.
- Mobile e iOS só leem o manifesto ou o plist. O binário do app não é analisado.
- A detecção de segredos usa padrões e entropia, então pode ter falso positivo ou falso negativo. A palavra "fake" **não** é tratada como valor de exemplo.
- O mesmo segredo repetido no mesmo arquivo conta uma vez só na comparação.


## 9. Hacker AI 1.0 (planejamento + 12 módulos + verificação)
```
cyberswarm hacker demo
cyberswarm hacker --goal "auditar laboratório completo"
```
Guia completo: `docs/HACKER_AI.md`. Ferramentas: `docs/FERRAMENTAS.md`. Plano: `docs/HACKER_AI_PLANO.md`. Auditoria do 0.3: `docs/AUDITORIA_0.3.md`. Números 0.3 × 1.0: `docs/COMPARATIVO.md`. Mensagens: `docs/INTERFACES.md`.

## 10. Hacker AI 1.1 — validação externa
`cyberswarm hacker labs` lista os laboratórios; resultados honestos por laboratório em `docs/VALIDACAO_EXTERNA.md`
(Juice Shop, WebGoat, VAmPI, DVGA, InsecureBankv2; crAPI não rodado por exigir Docker). Ferramentas externas: `docs/FERRAMENTAS_EXTERNAS.md`.
Mudanças no núcleo (aditivas): `checks.py` (novos checks) e `cli.py` (subcomandos). Piloto com cliente: `docs/PILOTO.md`.

## 11. CyberSwarm Control 1.0 (painel PWA no celular)
`cyberswarm control init|adduser|serve` — ver `docs/CONTROL.md`. Escuta só em 127.0.0.1 por padrão; sem terminal remoto.

## 12. Fundação 2.0 (Etapa C)
Agente `sca` (dependências vulneráveis via OSV-Scanner/Trivy/Grype, se instalados), fila persistente com retomada
(`python -m cyberswarm.v2.run`), cache, modo determinístico, adaptador de modelo desligado, confiança e benchmarks.
Ver `docs/FERRAMENTAS_2.0.md` e `docs/PROGRESSO.md`. Mudanças no núcleo: `agents/sca.py` (novo), 1 check em `checks.py`, 1 import em `registry.py`.
