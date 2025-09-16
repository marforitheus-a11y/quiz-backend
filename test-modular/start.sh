#!/bin/bash
# Script de inicialização para teste modular

echo "🚀 INICIANDO TESTE MODULAR DO QUIZ"
echo "=================================="

# Verificar se .env existe
if [ ! -f ".env" ]; then
    echo "⚠️  Arquivo .env não encontrado!"
    echo "📋 Copiando .env.example para .env..."
    cp .env.example .env
    echo "✅ Arquivo .env criado. Configure as variáveis de ambiente!"
    echo ""
fi

# Verificar se node_modules existe
if [ ! -d "node_modules" ]; then
    echo "📦 Instalando dependências..."
    npm install
    echo ""
fi

echo "🌐 Iniciando servidor modular na porta 4000..."
echo "📡 Health check: http://localhost:4000/health"
echo "🔐 Auth endpoints: http://localhost:4000/auth/*"
echo "❓ Quiz endpoints: http://localhost:4000/quiz/*"
echo ""
echo "Para testar:"
echo "curl http://localhost:4000/health"
echo ""

node app.js
