const axios = require('axios');

const API_URL = 'https://quiz-api-z4ri.onrender.com';

async function createAdminUser() {
    console.log('👤 Criando usuário admin...\n');
    
    // 1. Tentar criar usuário via signup com campos completos
    try {
        console.log('📝 Tentando signup com campos completos...');
        
        const signupData = {
            name: 'Administrador',
            username: 'admin',
            email: 'admin@quiz.com',
            password: 'admin123',
            consents: {
                essential: true,
                termsAccepted: true,
                privacyPolicyAccepted: true,
                performanceAnalysis: false,
                personalization: false,
                marketingEmails: false,
                analyticsCookies: false
            },
            gdprCompliance: {
                ipAddress: '127.0.0.1',
                userAgent: 'Test Script',
                timestamp: new Date().toISOString()
            }
        };
        
        const signupResponse = await axios.post(`${API_URL}/signup`, signupData);
        console.log('✅ Signup realizado com sucesso!');
        console.log('📊 Response:', signupResponse.data);
        
        // Agora tentar fazer login
        console.log('\n🔐 Tentando login com credenciais criadas...');
        const loginResponse = await axios.post(`${API_URL}/login`, {
            email: 'admin@quiz.com',
            password: 'admin123'
        });
        
        console.log('✅ Login funcionou!');
        console.log('🎫 Token recebido:', !!loginResponse.data.token);
        console.log('👤 User data:', loginResponse.data.user);
        
        return loginResponse.data.token;
        
    } catch (signupError) {
        console.log('❌ Erro no signup:', signupError.response?.status, signupError.response?.data);
        
        // Talvez o usuário já existe, tentar login direto
        console.log('\n🔄 Tentando login direto (usuário pode já existir)...');
        
        try {
            const loginResponse = await axios.post(`${API_URL}/login`, {
                email: 'admin@quiz.com',
                password: 'admin123'
            });
            
            console.log('✅ Login direto funcionou!');
            return loginResponse.data.token;
            
        } catch (loginError) {
            console.log('❌ Login direto também falhou:', loginError.response?.status, loginError.response?.data);
        }
    }
    
    // 2. Tentar com outras variações de dados
    const variations = [
        { 
            name: 'Admin', 
            username: 'administrador', 
            email: 'administrador@quiz.com', 
            password: 'admin123',
            consents: {
                essential: true,
                termsAccepted: true,
                privacyPolicyAccepted: true,
                performanceAnalysis: false,
                personalization: false,
                marketingEmails: false,
                analyticsCookies: false
            }
        },
        { 
            name: 'Test Admin', 
            username: 'testadmin', 
            email: 'test@admin.com', 
            password: 'test123',
            consents: {
                essential: true,
                termsAccepted: true,
                privacyPolicyAccepted: true,
                performanceAnalysis: false,
                personalization: false,
                marketingEmails: false,
                analyticsCookies: false
            }
        }
    ];
    
    for (const variation of variations) {
        try {
            console.log(`\n📝 Tentando criar: ${variation.email}`);
            await axios.post(`${API_URL}/signup`, variation);
            
            console.log('✅ Usuário criado! Tentando login...');
            const loginResponse = await axios.post(`${API_URL}/login`, {
                email: variation.email,
                password: variation.password
            });
            
            console.log('✅ Login funcionou com esta variação!');
            return loginResponse.data.token;
            
        } catch (error) {
            console.log(`❌ Falhou para ${variation.email}:`, error.response?.status);
        }
    }
    
    return null;
}

async function main() {
    const token = await createAdminUser();
    
    if (token) {
        console.log('\n🎉 Sucesso! Agora testando funcionalidades...');
        
        // Testar endpoint protegido
        try {
            const metricsResponse = await axios.get(`${API_URL}/api/admin/metrics`, {
                headers: { 'Authorization': `Bearer ${token}` }
            });
            console.log('✅ Métricas funcionaram:', metricsResponse.data);
            
        } catch (error) {
            console.log('❌ Erro nas métricas:', error.response?.status, error.response?.data);
        }
        
    } else {
        console.log('\n💡 Nenhuma credencial funcionou. Possíveis causas:');
        console.log('   - O banco de dados está vazio');
        console.log('   - As correções não foram aplicadas no deploy');
        console.log('   - Há um problema na validação de campos');
    }
}

main();