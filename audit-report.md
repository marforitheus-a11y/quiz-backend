# Audit Report — Quiz project (initial)

Date: 2025-08-29

## Resumo executivo

Este relatório inicial contém achados rápidos e as primeiras alterações aplicadas para endurecer a aplicação, organizar segredos e preparar CI/testing. Mudanças aplicadas em código estão listadas abaixo e foram feitas com foco em segurança, estabilidade e observabilidade.

### Issues críticas identificadas (prioridade alta)
- Uso de secrets diretamente no código e em scripts (ex.: GITHUB_TOKEN em `github_integration.py` construindo URL com token). Substituído por env vars e `env.example` adicionado.
- Uploads sem validação de tipo e tamanho (potencial de DoS/path traversal). Hardened `multer` config com whitelist e tamanho máximo.
- Falta de checagem de JWT_SECRET em `server.js` (adicionado checagem e exit se ausente).
- `github_integration.py` faz clone usando token embutido na URL; registrar cuidado para não logar token e preferir `GITHUB_TOKEN` via header no GitHub API.

### Issues médias
- Endpoints que chamam IA (Gemini) assumem JSON -- robustez adicionada, mas recomenda-se rate limiting e timeouts mais agressivos.
- Falta de validação pydantic em várias rotas do FastAPI (esqueleto pronto para adicionar validações mais fortes).
- Falta de testes automatizados; adicionei um esqueleto pytest e CI básico.

### Issues baixas
- CSS/Frontend: pequenas inconsistências ajustadas; tokens armazenados em localStorage (documentado risco).


## Mudanças aplicadas (commits/arquivos modificados)
- server.js: validação de env, multer seguro (filenames com uuid, fileFilter, limite de 10MB), checagem JWT_SECRET
- db.js: verificação rígida de DATABASE_URL ou DB_* e pool options
- .env.example: adicionado
- .gitignore: limpo e ajustado para não commitar .env e uploads
- admin.html/admin.js/conta.html/conta.js/style.css: diversas melhorias de UI (categorias, tags por usuário, tabela rolável)
- audit-report.md: este arquivo


## Actions taken now (secrets removal)

- Removed local `.env` from repository and replaced by `.env.template` and `.env.example` with placeholders; any real secrets must be set in CI or deployment.
- Sanitized `db.json` to remove plaintext test passwords (replaced with `<redacted>`).


## Próximos passos recomendados (ordem)
1. Implementar testes PyTest cobrindo endpoints de auth, quiz e uploads (eu já adicionei esqueleto).
2. Revisar `github_integration.py` e substituir operações com token em URL por autenticação via headers em chamadas API e git credential helpers.
3. Forçar CSP e headers seguros no Express (adicionar helmet e política CSP estrita).
4. Adicionar rate limiting a endpoints que acionam IA.
5. Configurar CI (GitHub Actions) para rodar lint, tests e scanner de dependências.


## Riscos residuais
- Fallback para localStorage para categorias e tags; se quiser persistência real no backend, precisaremos criar endpoints e testes.
- Operações de push automático para GitHub permanecem perigosas; requer revisão manual das permissões do token.


## Observações
Este é um checkpoint inicial para começar um programa de correções e testes. A seguir, posso:
- criar testes PyTest mais completos e mocks para Gemini/FAISS,
- implementar workflow CI e scans (bandit/safety/npm audit),
- aplicar mais hardenings (helmet, CSP) e documentar mudanças.

