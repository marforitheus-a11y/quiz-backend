const axios = require('axios');

async function waitAndTest() {
    console.log('⏳ Aguardando redeploy... (30 segundos)');
    
    // Aguardar 30 segundos para o deploy
    await new Promise(resolve => setTimeout(resolve, 30000));
    
    console.log('🔄 Testando login após redeploy...\n');
    
    const API_URL = 'https://quiz-api-z4ri.onrender.com';
    
    // Testar login com o usuário admin que criamos
    try {
        const loginResponse = await axios.post(`${API_URL}/login`, {
            email: 'admin@quiz.com',
            password: 'admin123'
        });
        
        console.log('✅ Login funcionou após redeploy!');
        console.log('👤 User:', loginResponse.data.user);
        console.log('🎫 Token:', !!loginResponse.data.token);
        
        if (loginResponse.data.token) {
            // Testar endpoint protegido
            try {
                const metricsResponse = await axios.get(`${API_URL}/api/admin/metrics`, {
                    headers: { 'Authorization': `Bearer ${loginResponse.data.token}` }
                });
                console.log('📊 Métricas:', metricsResponse.data);
                
            } catch (metricsError) {
                console.log('❌ Métricas falharam (normal se não for admin):', metricsError.response?.status);
            }
        }
        
    } catch (loginError) {
        console.log('❌ Login ainda falhando após redeploy:', loginError.response?.status, loginError.response?.data);
        
        // Se ainda falhar, tentar criar um novo usuário
        console.log('\n🔄 Tentando criar um novo usuário de teste...');
        
        try {
            const newSignup = await axios.post(`${API_URL}/signup`, {
                name: 'Teste Redeploy',
                username: 'testeredeploy',
                email: 'teste@redeploy.com',
                password: 'teste123',
                consents: {
                    essential: true,
                    termsAccepted: true,
                    privacyPolicyAccepted: true,
                    performanceAnalysis: false,
                    personalization: false,
                    marketingEmails: false,
                    analyticsCookies: false
                }
            });
            
            console.log('✅ Novo usuário criado!');
            
            // Tentar login imediatamente
            const immediateLogin = await axios.post(`${API_URL}/login`, {
                email: 'teste@redeploy.com',
                password: 'teste123'
            });
            
            console.log('✅ Login imediato funcionou!');
            console.log('👤 User:', immediateLogin.data.user);
            
        } catch (newUserError) {
            console.log('❌ Novo usuário também falhou:', newUserError.response?.status, newUserError.response?.data);
        }
    }
}

waitAndTest();