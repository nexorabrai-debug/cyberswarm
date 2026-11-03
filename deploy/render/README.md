# Deploy Render Free (sem cartão)

Ver `docs/IMPLANTACAO_SEM_CARTAO.md` § Render.

- `render.yaml` — Blueprint Web Service free
- `Dockerfile` — usa o Dockerfile da raiz do projeto
- Limite crítico: filesystem efémero + sleep 15 min → SQLite perde-se no spin-down
