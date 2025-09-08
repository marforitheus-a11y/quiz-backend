// Script de teste para o endpoint de métricas
require('dotenv').config();
const axios = require('axios');

async function testMetrics() {
    try {
        console.log('=== TESTE DO ENDPOINT DE MÉTRICAS ===');
        
        // 1. Testar se o servidor está rodando
        console.log('\n1. Testando conexão com servidor...');
        try {
            const healthCheck = await axios.get('http://localhost:3000/');
            console.log('✅ Servidor está rodando');
        } catch (err) {
            console.log('❌ Servidor não está rodando:', err.message);
            return;
        }
        
        // 2. Fazer login como admin
        console.log('\n2. Fazendo login como admin...');
        let token;
        try {
            const loginResponse = await axios.post('http://localhost:3000/login', {
                username: 'local_admin',
                password: 'AdminPass123!'
            });
            token = loginResponse.data.token;
            console.log('✅ Login realizado com sucesso');
            console.log('Token:', token.substring(0, 20) + '...');
        } catch (err) {
            console.log('❌ Erro no login:', err.response?.data || err.message);
            return;
        }
        
        // 3. Testar endpoint simples
        console.log('\n3. Testando endpoint simples...');
        try {
            const simpleResponse = await axios.get('http://localhost:3000/admin/dashboard/simple', {
                headers: { 'Authorization': `Bearer ${token}` }
            });
            console.log('✅ Endpoint simples funcionando:', simpleResponse.data);
        } catch (err) {
            console.log('❌ Erro no endpoint simples:', err.response?.data || err.message);
        }
        
        // 4. Testar endpoint de métricas
        console.log('\n4. Testando endpoint de métricas...');
        try {
            const metricsResponse = await axios.get('http://localhost:3000/admin/dashboard/metrics', {
                headers: { 'Authorization': `Bearer ${token}` }
            });
            console.log('✅ Endpoint de métricas funcionando');
            console.log('Dados recebidos:');
            console.log('- Total de usuários:', metricsResponse.data.overview.totalUsers);
            console.log('- Total de questões:', metricsResponse.data.overview.totalQuestions);
            console.log('- Total de categorias:', metricsResponse.data.overview.totalCategories);
            console.log('- Categorias:', metricsResponse.data.questionStats.byCategory.map(c => c.category).slice(0, 3));
            console.log('- Dificuldades:', metricsResponse.data.questionStats.byDifficulty.map(d => `${d.difficulty}: ${d.count}`));
        } catch (err) {
            console.log('❌ Erro no endpoint de métricas:', err.response?.data || err.message);
            if (err.response?.status) {
                console.log('Status:', err.response.status);
                console.log('Headers:', err.response.headers);
            }
        }
        
    } catch (err) {
        console.error('Erro geral:', err.message);
    }
}

testMetrics();
