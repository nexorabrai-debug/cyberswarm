# Manual de operação — CyberSwarm 2.0 + Hacker AI

## Papéis
- **owner**: cria missões, aprova, configura modelos, finanças.
- **viewer**: só leitura (opcionalmente preso a clientes).

## Fluxo típico
1. Cadastre o cliente em **Escopos** (termo, validade, hosts sem curinga).
2. No **Chat** ou **Hacker AI**, descreva o objetivo.
3. O planner (regras; IA opcional) monta o plano.
4. Testes ativos fora de 127.0.0.1 geram **Aprovação**.
5. O **worker** executa; veja **Tarefas** / **Achados** / **PDF**.

## Comandos de chat
- objetivo livre → nova missão
- `status` → fila recente
- `pausar #ID` / `cancelar #ID`
- `explica #ID` → resumo em pt-BR
- `ajuda`

## Modo sem IA
Em **Ajustes**, ligue «modo determinístico». Operações complexas exigem plano pré-aprovado em `preapproved_plans.json` (hash SHA-256 do plano). Tarefas já autorizadas continuam.

## Provedores de IA
none (padrão) → ollama (local) → OpenAI-compatível (HTTPS + chave só no servidor). Cadeia de fallback em Ajustes. **Não depende do Grok.**

## Worker independente
`cyberswarm worker --data DIR` — obrigatório se usar `--no-workers` no serve. Sobrevive ao fechar o celular.

## Segurança operacional
- Só lab 127.0.0.1 ou cliente com termo vigente.
- Nunca cole senhas de cliente no chat/escopo.
- Prefira HTTPS (`--tls`) e senha ≥ 10 caracteres.
