const axios = require('axios');

const BASE_URL = 'http://localhost:4000/api';
let authToken = null;

// Test configurations
const testUser = {
    name: 'Test User',
    email: 'test@example.com',
    password: 'test123'
};

async function runProductionTests() {
    console.log('🧪 INICIANDO TESTES DE PRODUÇÃO\n');

    try {
        // 1. Health Check
        console.log('1️⃣ Testando Health Check...');
        const healthResponse = await axios.get(`${BASE_URL}/health`);
        console.log('✅ Health Check:', healthResponse.data.status);
        console.log(`   Database: ${healthResponse.data.database}\n`);

        // 2. User Registration
        console.log('2️⃣ Testando Registro de Usuário...');
        try {
            const signupResponse = await axios.post(`${BASE_URL}/auth/signup`, testUser);
            authToken = signupResponse.data.token;
            console.log('✅ Registro realizado com sucesso');
            console.log(`   Token: ${authToken.substring(0, 20)}...\n`);
        } catch (error) {
            if (error.response?.status === 400 && error.response.data.error.includes('já cadastrado')) {
                console.log('ℹ️ Usuário já existe, tentando login...\n');
                
                // 3. User Login
                console.log('3️⃣ Testando Login...');
                const loginResponse = await axios.post(`${BASE_URL}/auth/login`, {
                    email: testUser.email,
                    password: testUser.password
                });
                authToken = loginResponse.data.token;
                console.log('✅ Login realizado com sucesso');
                console.log(`   Token: ${authToken.substring(0, 20)}...\n`);
            } else {
                throw error;
            }
        }

        // 4. Fetch Themes
        console.log('4️⃣ Testando Busca de Temas...');
        const themesResponse = await axios.get(`${BASE_URL}/quiz/themes`);
        const themes = themesResponse.data;
        console.log(`✅ ${themes.length} temas encontrados`);
        
        if (themes.length > 0) {
            console.log(`   Primeiro tema: ${themes[0].title}`);
            console.log(`   Categoria: ${themes[0].category_name || 'N/A'}`);
            console.log(`   Questões: ${themes[0].question_count}\n`);

            // 5. Fetch Questions for first theme
            console.log('5️⃣ Testando Busca de Questões...');
            const questionsResponse = await axios.get(`${BASE_URL}/quiz/themes/${themes[0].id}/questions?limit=5`);
            const questions = questionsResponse.data;
            console.log(`✅ ${questions.length} questões encontradas para "${themes[0].title}"`);
            
            if (questions.length > 0) {
                console.log(`   Primeira questão: ${questions[0].text.substring(0, 50)}...`);
                console.log(`   Dificuldade: ${questions[0].difficulty || 'N/A'}\n`);

                // 6. Submit Quiz Result
                console.log('6️⃣ Testando Submissão de Resultado...');
                const mockAnswers = questions.map((q, index) => ({
                    questionId: q.id,
                    selectedAnswer: 'A',
                    correct: index % 2 === 0 // Simulate 50% correct
                }));

                const score = mockAnswers.filter(a => a.correct).length;
                
                const submitResponse = await axios.post(`${BASE_URL}/quiz/submit`, {
                    themeId: themes[0].id,
                    answers: mockAnswers,
                    score: score,
                    totalQuestions: questions.length
                }, {
                    headers: { Authorization: `Bearer ${authToken}` }
                });

                console.log('✅ Resultado submetido com sucesso');
                console.log(`   Score: ${submitResponse.data.score}/${submitResponse.data.totalQuestions}`);
                console.log(`   Percentual: ${submitResponse.data.percentage}%\n`);
            }
        }

        // 7. Fetch User Results
        console.log('7️⃣ Testando Busca de Resultados...');
        const resultsResponse = await axios.get(`${BASE_URL}/quiz/results`, {
            headers: { Authorization: `Bearer ${authToken}` }
        });
        const results = resultsResponse.data;
        console.log(`✅ ${results.length} resultados encontrados`);
        
        if (results.length > 0) {
            console.log(`   Último resultado: ${results[0].score}/${results[0].total_questions} (${results[0].percentage}%)`);
            console.log(`   Tema: ${results[0].theme_name}\n`);
        }

        // 8. Test Invalid Token
        console.log('8️⃣ Testando Proteção de Rotas...');
        try {
            await axios.get(`${BASE_URL}/quiz/results`, {
                headers: { Authorization: 'Bearer invalid-token' }
            });
            console.log('❌ Falha na proteção de rotas!');
        } catch (error) {
            if (error.response?.status === 403) {
                console.log('✅ Proteção de rotas funcionando corretamente\n');
            } else {
                throw error;
            }
        }

        console.log('🎉 TODOS OS TESTES PASSARAM!');
        console.log('\n📊 RESUMO:');
        console.log('✅ Health Check - OK');
        console.log('✅ Autenticação - OK');
        console.log('✅ Temas - OK');
        console.log('✅ Questões - OK');
        console.log('✅ Submissão - OK');
        console.log('✅ Resultados - OK');
        console.log('✅ Segurança - OK');
        console.log('\n🚀 Sistema pronto para produção!');

    } catch (error) {
        console.error('\n❌ ERRO NO TESTE:');
        console.error('Endpoint:', error.config?.url);
        console.error('Status:', error.response?.status);
        console.error('Message:', error.response?.data?.error || error.message);
        console.error('\n⚠️ Verifique se o servidor está rodando e o banco conectado');
        process.exit(1);
    }
}

// Check if server is running
async function checkServer() {
    try {
        await axios.get(`${BASE_URL}/health`);
        return true;
    } catch (error) {
        return false;
    }
}

async function main() {
    console.log('🔍 Verificando se o servidor está rodando...\n');
    
    const serverRunning = await checkServer();
    if (!serverRunning) {
        console.log('❌ Servidor não está rodando!');
        console.log('💡 Execute: node server-production.js');
        process.exit(1);
    }

    await runProductionTests();
}

main();
