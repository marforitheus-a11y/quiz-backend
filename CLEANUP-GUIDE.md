# QUIZ SYSTEM - CLEANUP GUIDE

## ✅ ARQUIVOS PARA MANTER (PRODUÇÃO)

### Backend Essenciais:
- `server-production.js` - Servidor principal de produção
- `package.json` - Dependências
- `package-lock.json` - Lock das dependências
- `.env.production` - Configuração de produção
- `.gitignore` - Controle Git
- `README.md` - Documentação
- `app/` - Código modular organizado (se ainda usando)
- `migrations/` - Migrações do banco de dados

### Frontend Essenciais:
- `index.html` - Página principal
- `quiz.html` - Interface do quiz
- `admin.html` - Painel administrativo
- `login.js` - Sistema de autenticação
- `quiz.js` - Lógica do quiz
- `admin.js` - Funcionalidades admin
- `style.css` - Estilos principais
- `assets/` - Recursos estáticos

## 🗑️ ARQUIVOS PARA REMOVER (TESTES E TEMPORÁRIOS)

### Backend - Arquivos de Teste:
- `app-database-fixed.js` ❌
- `app-database.js` ❌
- `check_*.js` (todos os arquivos check) ❌
- `test_*.js` (todos os arquivos test) ❌
- `comprehensive_test.js` ❌
- `simple_test.js` ❌
- `diagnose_*.js` ❌
- `fix_*.js` ❌
- `execute_*.js` ❌
- `create_token.js` ❌
- `reset_password.js` ❌
- `token_test.txt` ❌
- `test-modular/` (pasta inteira) ❌

### Backend - Arquivos Específicos de Deploy/Outros:
- `rag-integration.js` ❌
- `rag-system.js` ❌
- `requirements.txt` ❌ (Python)
- `server.js` ❌ (versão antiga)
- `db.js` ❌ (versão antiga)
- `GITHUB_TOKEN` ❌

### Frontend - Arquivos de Teste:
- `test-frontend/` (pasta inteira) ❌
- `test-*.html` ❌
- `test-*.js` ❌
- `debug-admin.js` ❌
- `test-normalization.js` ❌
- `test-delete-script.js` ❌
- `admin_token.txt` ❌
- `token.txt` ❌

### Frontend - Arquivos de Desenvolvimento:
- `new-design/` (se não usando) ❌
- `improvements/` ❌
- `src/` (se duplicado) ❌
- Arquivos `.jpg/.svg` soltos ❌

### Documentação Temporária:
- `audit-report.md` ❌
- `FIX-*.md` ❌
- `TESTE-*.md` ❌
- `README-MODERNIZACAO-COMPLETA.md` ❌
- `LGPD-CHECKLIST.md` (se não aplicável) ❌
- `README-LGPD.md` (se não aplicável) ❌

## 🔧 COMANDOS PARA LIMPEZA

### PowerShell (Windows):
```powershell
# Backend cleanup
cd C:\Users\Matheus\Desktop\backup\quiz\quiz-backend
Remove-Item -Path "app-database*.js", "check_*.js", "test_*.js", "comprehensive_test.js", "simple_test.js", "diagnose_*.js", "fix_*.js", "execute_*.js", "create_token.js", "reset_password.js", "token_test.txt", "rag-*.js", "requirements.txt", "server.js", "db.js", "GITHUB_TOKEN" -Force
Remove-Item -Path "test-modular" -Recurse -Force

# Frontend cleanup  
cd C:\Users\Matheus\Desktop\backup\quiz\quiz-frontend
Remove-Item -Path "test-*", "debug-*.js", "admin_token.txt", "token.txt", "*.jpg", "*.svg" -Force
Remove-Item -Path "test-frontend", "improvements" -Recurse -Force
```

## 📁 ESTRUTURA FINAL LIMPA

```
quiz-backend/
├── server-production.js     # ✅ Servidor principal
├── package.json            # ✅ Dependências
├── .env.production         # ✅ Configuração
├── migrations/             # ✅ Migrações DB
└── README.md              # ✅ Documentação

quiz-frontend/
├── index.html             # ✅ Página principal  
├── quiz.html              # ✅ Interface quiz
├── admin.html             # ✅ Painel admin
├── login.js               # ✅ Autenticação
├── quiz.js                # ✅ Lógica quiz
├── admin.js               # ✅ Admin functions
├── style.css              # ✅ Estilos
└── assets/                # ✅ Recursos
```

## ⚠️ ANTES DE DELETAR:
1. Faça backup completo
2. Teste o `server-production.js` 
3. Verifique se todas as funcionalidades funcionam
4. Confirme que não há dependências ocultas
