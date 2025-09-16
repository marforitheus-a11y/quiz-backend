const axios = require('axios');

const BACKEND_URL = 'https://quiz-backend-ov0o.onrender.com';

async function testLoginFunctionality() {
    console.log('🔐 Testando funcionalidade de login em produção...\n');
    
    try {
        // 1. Testar login de usuário normal
        console.log('👤 Testando login de usuário normal...');
        
        const normalUserLogin = await axios.post(`${BACKEND_URL}/login`, {
            email: 'bruna@example.com',  // assumindo que existe um usuário normal
            password: 'senha123'
        }).catch(err => ({
            status: err.response?.status,
            data: err.response?.data,
            error: true
        }));
        
        if (normalUserLogin.error) {
            console.log(`❌ Erro no login normal: ${normalUserLogin.status} - ${JSON.stringify(normalUserLogin.data)}`);
        } else {
            console.log(`✅ Login normal funcionou! Token recebido: ${normalUserLogin.data.token ? 'Sim' : 'Não'}`);
        }
        
        // 2. Testar login de admin
        console.log('\n👑 Testando login de admin...');
        
        const adminLogin = await axios.post(`${BACKEND_URL}/login`, {
            email: 'admin@quiz.com',
            password: 'admin123'
        }).catch(err => ({
            status: err.response?.status,
            data: err.response?.data,
            error: true
        }));
        
        if (adminLogin.error) {
            console.log(`❌ Erro no login admin: ${adminLogin.status} - ${JSON.stringify(adminLogin.data)}`);
        } else {
            console.log(`✅ Login admin funcionou! Token recebido: ${adminLogin.data.token ? 'Sim' : 'Não'}`);
        }
        
        // 3. Testar endpoint de métricas (que usa role-based auth)
        if (!adminLogin.error && adminLogin.data.token) {
            console.log('\n📊 Testando endpoint de métricas com token admin...');
            
            const metricsTest = await axios.get(`${BACKEND_URL}/api/admin/metrics`, {
                headers: {
                    'Authorization': `Bearer ${adminLogin.data.token}`
                }
            }).catch(err => ({
                status: err.response?.status,
                data: err.response?.data,
                error: true
            }));
            
            if (metricsTest.error) {
                console.log(`❌ Erro nas métricas: ${metricsTest.status}`);
            } else {
                console.log(`✅ Métricas funcionando! Usuários totais: ${metricsTest.data.totalUsers || 'N/A'}`);
            }
        }
        
        // 4. Testar endpoint público - testar se o servidor está realmente rodando
        console.log('\n🌐 Testando se o servidor está rodando...');
        
        const serverTest = await axios.get(`${BACKEND_URL}/`).catch(err => ({
            status: err.response?.status || 'OFFLINE',
            data: err.response?.data || 'Servidor não responde',
            error: true
        }));
        
        if (serverTest.error) {
            console.log(`❌ Servidor parece estar offline: ${serverTest.status} - ${serverTest.data}`);
            console.log('💡 Dica: O deploy no Render pode estar falhando ou ainda não foi aplicado.');
        } else {
            console.log(`✅ Servidor está respondendo!`);
        }
        
    } catch (error) {
        console.error('❌ Erro geral no teste:', error.message);
    }
}

testLoginFunctionality();