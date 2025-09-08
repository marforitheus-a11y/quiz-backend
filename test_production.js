// Teste do dashboard em produção
const axios = require('axios');

async function testProductionDashboard() {
    try {
        console.log('=== TESTE DO DASHBOARD EM PRODUÇÃO ===');
        console.log('Frontend: https://quiz-frontend-nu-wheat.vercel.app');
        console.log('Backend: https://quiz-api-z4ri.onrender.com');
        
        // 1. Verificar se o backend está funcionando
        console.log('\n1. Testando conexão com backend...');
        try {
            const response = await axios.get('https://quiz-api-z4ri.onrender.com/');
            console.log('✅ Backend está respondendo');
        } catch (err) {
            console.log('❌ Erro no backend:', err.message);
            return;
        }
        
        // 2. Tentar fazer login (se tiver credenciais)
        console.log('\n2. Testando login de admin...');
        let token;
        try {
            const loginResponse = await axios.post('https://quiz-api-z4ri.onrender.com/login', {
                username: 'local_admin',
                password: 'AdminPass123!'
            });
            token = loginResponse.data.token;
            console.log('✅ Login bem-sucedido');
        } catch (err) {
            console.log('❌ Erro no login:', err.response?.data?.message || err.message);
            console.log('   Isso é normal se o usuário admin não existir em produção');
        }
        
        // 3. Testar endpoint público de categorias (para verificar se o banco está funcionando)
        console.log('\n3. Testando dados do banco...');
        try {
            const categoriesResponse = await axios.get('https://quiz-api-z4ri.onrender.com/categories');
            console.log('✅ Categorias encontradas:', categoriesResponse.data.length);
            if (categoriesResponse.data.length > 0) {
                console.log('   Exemplos:', categoriesResponse.data.slice(0, 3).map(c => c.name));
            }
        } catch (err) {
            console.log('❌ Erro ao buscar categorias:', err.response?.data || err.message);
        }
        
        // 4. Testar endpoint de questões
        console.log('\n4. Testando questões...');
        try {
            const questionsResponse = await axios.get('https://quiz-api-z4ri.onrender.com/questions?limit=1');
            console.log('✅ Questões disponíveis');
            console.log('   Total encontrado:', questionsResponse.data.length);
        } catch (err) {
            console.log('❌ Erro ao buscar questões:', err.response?.data || err.message);
        }
        
        console.log('\n=== RESUMO ===');
        console.log('- Backend está funcionando');
        console.log('- O dashboard deve mostrar dados reais se você fizer login como admin');
        console.log('- Se os dados ainda aparecem como mock, pode ser cache do navegador');
        console.log('- Tente fazer um refresh forçado (Ctrl+F5) na página do admin');
        
    } catch (err) {
        console.error('Erro geral:', err.message);
    }
}

testProductionDashboard();
