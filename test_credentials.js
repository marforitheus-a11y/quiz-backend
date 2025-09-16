const axios = require('axios');

const API_URL = 'https://quiz-api-z4ri.onrender.com';

async function testCredentials() {
    console.log('🔐 Testando diferentes credenciais...\n');
    
    const credentialsList = [
        { email: 'admin@quiz.com', password: 'admin123', desc: 'Admin padrão' },
        { email: 'admin@example.com', password: 'admin123', desc: 'Admin exemplo 1' },
        { email: 'admin@test.com', password: 'admin123', desc: 'Admin exemplo 2' },
        { email: 'brunaamor', password: 'brunaamor123', desc: 'Admin brunaamor' },
        { email: 'admin', password: 'admin', desc: 'Admin simples' },
        { email: 'matheus@example.com', password: 'senha123', desc: 'Matheus teste' }
    ];
    
    for (const cred of credentialsList) {
        try {
            console.log(`Testando: ${cred.desc} (${cred.email})`);
            
            const response = await axios.post(`${API_URL}/login`, {
                email: cred.email,
                password: cred.password
            });
            
            console.log(`✅ SUCESSO! ${cred.desc} funcionou!`);
            console.log(`Token: ${response.data.token ? 'Recebido' : 'Não recebido'}`);
            console.log(`User: ${JSON.stringify(response.data.user || 'N/A')}`);
            console.log('');
            
            // Se conseguiu logar, testar um endpoint protegido
            if (response.data.token) {
                try {
                    const metricsTest = await axios.get(`${API_URL}/api/admin/metrics`, {
                        headers: { 'Authorization': `Bearer ${response.data.token}` }
                    });
                    console.log('✅ Métricas funcionaram também!');
                } catch (metricsError) {
                    console.log('❌ Métricas falharam:', metricsError.response?.status);
                }
            }
            
            break; // Se encontrou credenciais válidas, para o loop
            
        } catch (error) {
            console.log(`❌ ${cred.desc}: ${error.response?.status} - ${error.response?.data?.message || 'Erro'}`);
        }
    }
    
    // Testar endpoints disponíveis
    console.log('\n🌐 Testando endpoints disponíveis...');
    
    const endpoints = [
        '/health',
        '/quiz/themes',
        '/themes',
        '/api/themes',
        '/quiz/user-stats',
        '/user-stats',
        '/api/user-stats'
    ];
    
    for (const endpoint of endpoints) {
        try {
            const response = await axios.get(`${API_URL}${endpoint}`);
            console.log(`✅ ${endpoint}: ${response.status} - ${JSON.stringify(response.data).substring(0, 100)}...`);
        } catch (error) {
            console.log(`❌ ${endpoint}: ${error.response?.status || 'OFFLINE'}`);
        }
    }
}

testCredentials();