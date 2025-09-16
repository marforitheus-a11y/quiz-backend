const axios = require('axios');

async function quickTest() {
    const API_URL = 'https://quiz-api-z4ri.onrender.com';
    
    console.log('🔐 Testando login com usuário recém-criado...');
    
    try {
        const loginResponse = await axios.post(`${API_URL}/login`, {
            loginIdentifier: 'teste@redeploy.com',  // Campo correto!
            password: 'teste123'
        });
        
        console.log('✅ SUCCESS! Login funcionou!');
        console.log('👤 User:', JSON.stringify(loginResponse.data.user, null, 2));
        console.log('🎫 Token recebido:', !!loginResponse.data.token);
        
        // Agora o problema deve estar resolvido!
        console.log('\n🎉 O problema de login foi resolvido!');
        console.log('💡 Agora você pode tentar fazer login no frontend com:');
        console.log('   Email: teste@redeploy.com');
        console.log('   Senha: teste123');
        
    } catch (error) {
        console.log('❌ Login ainda falhando:', error.response?.status, error.response?.data);
        console.log('🤔 Isso indica que há um problema mais profundo no código de autenticação.');
    }
}

quickTest();