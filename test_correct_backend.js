const axios = require('axios');

const API_URL = 'https://quiz-api-z4ri.onrender.com';

async function testCorrectBackend() {
    console.log('🔍 Testando backend correto em:', API_URL);
    console.log('');
    
    try {
        // 1. Verificar se o servidor está online
        console.log('🌐 Verificando se o servidor está online...');
        const healthCheck = await axios.get(`${API_URL}/health`);
        console.log('✅ Servidor online!', healthCheck.data);
        console.log('');
        
        // 2. Tentar fazer login com credenciais válidas
        console.log('🔐 Testando login...');
        
        // Teste com credenciais de admin
        try {
            const adminLogin = await axios.post(`${API_URL}/login`, {
                email: 'admin@quiz.com',
                password: 'admin123'
            });
            
            console.log('✅ Login admin funcionou!');
            const token = adminLogin.data.token;
            
            // 3. Testar endpoint protegido com token
            console.log('🔒 Testando endpoint protegido...');
            const protectedTest = await axios.get(`${API_URL}/api/admin/metrics`, {
                headers: {
                    'Authorization': `Bearer ${token}`
                }
            });
            
            console.log('✅ Endpoint protegido funcionou!');
            console.log('📊 Métricas:', {
                totalUsers: protectedTest.data.totalUsers,
                hasData: !!protectedTest.data
            });
            
        } catch (loginError) {
            console.log('❌ Erro no login admin:', loginError.response?.status, loginError.response?.data);
        }
        
        // 4. Testar login com usuário normal (se existir)
        console.log('');
        console.log('👤 Testando login de usuário normal...');
        try {
            const userLogin = await axios.post(`${API_URL}/login`, {
                email: 'user@test.com',
                password: 'test123'
            });
            
            console.log('✅ Login de usuário normal funcionou!');
            
        } catch (userError) {
            console.log('ℹ️ Usuário normal não existe ou credenciais inválidas:', userError.response?.status);
        }
        
        // 5. Testar endpoint de temas (que apareceu no erro)
        console.log('');
        console.log('🎨 Testando endpoint de temas...');
        try {
            const themesTest = await axios.get(`${API_URL}/quiz/themes`);
            console.log('✅ Endpoint de temas funcionou!');
            console.log('📝 Temas encontrados:', themesTest.data?.length || 0);
            
        } catch (themesError) {
            console.log('❌ Erro no endpoint de temas:', themesError.response?.status, themesError.response?.data);
        }
        
    } catch (error) {
        console.error('❌ Erro geral:', error.message);
    }
}

testCorrectBackend();