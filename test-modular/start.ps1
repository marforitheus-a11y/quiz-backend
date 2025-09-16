# Script PowerShell para iniciar teste modular
Write-Host "🚀 INICIANDO TESTE MODULAR DO QUIZ" -ForegroundColor Green
Write-Host "==================================" -ForegroundColor Green

# Verificar se .env existe
if (-not (Test-Path ".env")) {
    Write-Host "⚠️  Arquivo .env não encontrado!" -ForegroundColor Yellow
    
    # Copiar configurações do projeto principal
    $mainEnvPath = "..\.env"
    if (Test-Path $mainEnvPath) {
        Write-Host "📋 Copiando .env do projeto principal..." -ForegroundColor Cyan
        Copy-Item $mainEnvPath ".env"
        
        # Alterar porta para 4000
        $envContent = Get-Content ".env"
        $envContent = $envContent -replace "PORT=3000", "PORT=4000"
        $envContent | Set-Content ".env"
        
        Write-Host "✅ Arquivo .env configurado com PORT=4000!" -ForegroundColor Green
    } else {
        Write-Host "📋 Copiando .env.example para .env..." -ForegroundColor Cyan
        Copy-Item ".env.example" ".env"
        Write-Host "⚠️  Configure as variáveis de ambiente no arquivo .env!" -ForegroundColor Yellow
    }
    Write-Host ""
}

# Verificar se node_modules existe
if (-not (Test-Path "node_modules")) {
    Write-Host "📦 Instalando dependências..." -ForegroundColor Cyan
    npm install
    Write-Host ""
}

Write-Host "🌐 Iniciando servidor modular na porta 4000..." -ForegroundColor Green
Write-Host "📡 Health check: http://localhost:4000/health" -ForegroundColor White
Write-Host "🔐 Auth endpoints: http://localhost:4000/auth/*" -ForegroundColor White
Write-Host "❓ Quiz endpoints: http://localhost:4000/quiz/*" -ForegroundColor White
Write-Host ""
Write-Host "Para testar no PowerShell:" -ForegroundColor Cyan
Write-Host "Invoke-RestMethod -Uri 'http://localhost:4000/health'" -ForegroundColor Gray
Write-Host ""

node app.js
