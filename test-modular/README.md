# 🧪 Quiz Backend - Teste Modular

## 📋 Sobre
Este é um **ambiente de teste isolado** da versão modular do Quiz Backend, criado para demonstrar a arquitetura otimizada sem afetar o projeto original.

## 🏗️ Arquitetura

```
test-modular/
├── config/
│   ├── database.js      # Conexão PostgreSQL
│   └── environment.js   # Configurações
├── controllers/
│   ├── authController.js    # Autenticação
│   └── quizController.js    # Quiz logic
├── routes/
│   ├── authRoutes.js    # /auth/* routes
│   └── quizRoutes.js    # /quiz/* routes
├── middlewares/
│   └── auth.js         # JWT middleware
├── app.js              # App principal (150 linhas vs 4218)
├── .env.example        # Configurações exemplo
└── start.ps1          # Script de inicialização
```

## ⚡ Melhorias vs Versão Original

| Aspecto | Original | Modular |
|---------|----------|---------|
| **Linhas de código** | 4.218 linhas | ~150 linhas |
| **Arquitetura** | Monolítica | MVC Modular |
| **Manutenibilidade** | Difícil | Fácil |
| **Testabilidade** | Limitada | Alta |
| **Separação de responsabilidades** | Baixa | Alta |
| **CORS** | Configuração complexa | Simples e clara |

## 🚀 Como Iniciar

### 1. Configurar ambiente
```bash
cd test-modular
copy ..\.env .env
# Editar PORT=4000 no .env
```

### 2. Instalar dependências
```bash
npm install
```

### 3. Iniciar servidor
```bash
# PowerShell
.\start.ps1

# Ou manualmente
node app.js
```

## 📡 Endpoints

### Health Check
```
GET /health
```

### Autenticação
```
POST /auth/login       # Login
POST /auth/register    # Registro
GET  /auth/me         # Perfil (protegido)
POST /auth/logout     # Logout (protegido)
```

### Quiz
```
GET  /quiz/themes      # Temas (protegido)
GET  /quiz/questions   # Questões (protegido)
GET  /quiz/user-stats  # Estatísticas (protegido)
POST /quiz/submit      # Submeter quiz (protegido)
```

## 🧪 Testes

### Testar Health
```powershell
Invoke-RestMethod -Uri "http://localhost:4000/health"
```

### Testar Login
```powershell
$body = @{
    loginIdentifier = "brunaamor"
    password = "123456"
} | ConvertTo-Json

$response = Invoke-RestMethod -Uri "http://localhost:4000/auth/login" -Method POST -ContentType "application/json" -Body $body
```

### Testar Temas (com token)
```powershell
$headers = @{ Authorization = "Bearer $($response.token)" }
Invoke-RestMethod -Uri "http://localhost:4000/quiz/themes" -Headers $headers
```

## 🎯 Vantagens da Arquitetura Modular

1. **📦 Separação clara de responsabilidades**
2. **🔧 Fácil manutenção e debug**
3. **🧪 Testabilidade individual de componentes**
4. **🚀 Performance otimizada**
5. **🔒 Segurança melhorada com middlewares específicos**
6. **📈 Escalabilidade horizontal**

## 🔄 Próximos Passos

Após validar este ambiente, você pode:
1. ✅ Migrar gradualmente do servidor original
2. ✅ Adicionar testes automatizados
3. ✅ Implementar cache Redis
4. ✅ Adicionar monitoring e logs
5. ✅ Configurar CI/CD

---

**Porta:** 4000 (diferente do original para não conflitar)
**Status:** Pronto para teste! 🎉
