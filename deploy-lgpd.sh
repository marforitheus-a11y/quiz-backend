#!/bin/bash
# Script de Deploy LGPD
# Este script deve ser executado no servidor de produção após o deploy

echo "🚀 Iniciando deploy LGPD..."

# 1. Aplicar migração do banco de dados
echo "📊 Aplicando migração LGPD..."
node run-lgpd-migration.js

if [ $? -eq 0 ]; then
    echo "✅ Migração aplicada com sucesso!"
else
    echo "❌ Erro na migração. Verifique a conexão com o banco."
    exit 1
fi

# 2. Reiniciar servidor para carregar novas rotas
echo "🔄 Reiniciando servidor..."
pm2 restart quiz-backend

# 3. Verificar se as rotas LGPD estão funcionando
echo "🔍 Testando APIs LGPD..."
sleep 5

# Teste básico das rotas (substitua pela URL real)
curl -s -o /dev/null -w "%{http_code}" "https://quiz-backend-1.onrender.com/health" || echo "⚠️  Aviso: Servidor pode ainda estar inicializando"

echo "🎉 Deploy LGPD concluído!"
echo ""
echo "📋 Próximos passos:"
echo "1. Testar formulário de cadastro com consentimentos"
echo "2. Verificar interface de gerenciamento: /gerenciar-consentimentos.html"
echo "3. Testar funcionalidades de exportação e exclusão"
echo "4. Monitorar logs de auditoria LGPD"
echo ""
echo "📞 Em caso de problemas, consulte README-LGPD.md"
