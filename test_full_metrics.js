const https = require('https');

function loginAndTestMetrics() {
    console.log('Fazendo login como admin na produção...');
    
    const loginData = JSON.stringify({
        username: 'local_admin',
        password: 'AdminPass123!'
    });
    
    const options = {
        hostname: 'quiz-api-z4ri.onrender.com',
        path: '/login',
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'Content-Length': Buffer.byteLength(loginData)
        }
    };
    
    const req = https.request(options, (res) => {
        let data = '';
        
        res.on('data', (chunk) => {
            data += chunk;
        });
        
        res.on('end', () => {
            console.log('Login Status:', res.statusCode);
            
            if (res.statusCode === 200) {
                try {
                    const response = JSON.parse(data);
                    console.log('✓ Login bem-sucedido!');
                    console.log('Token recebido:', response.token.substring(0, 50) + '...');
                    
                    // Agora testar o endpoint de métricas
                    testMetricsWithToken(response.token);
                } catch (err) {
                    console.log('Erro ao fazer parse do JSON:', err.message);
                    console.log('Resposta raw:', data);
                }
            } else {
                console.log('✗ Erro no login:', data);
            }
        });
    });
    
    req.on('error', (err) => {
        console.error('Erro na requisição de login:', err.message);
    });
    
    req.write(loginData);
    req.end();
}

function testMetricsWithToken(token) {
    console.log('\nTestando endpoint de métricas com token válido...');
    
    const options = {
        hostname: 'quiz-api-z4ri.onrender.com',
        path: '/admin/dashboard/metrics',
        method: 'GET',
        headers: {
            'Authorization': `Bearer ${token}`
        }
    };
    
    const req = https.request(options, (res) => {
        let data = '';
        
        res.on('data', (chunk) => {
            data += chunk;
        });
        
        res.on('end', () => {
            console.log('Metrics Status:', res.statusCode);
            
            if (res.statusCode === 200) {
                console.log('✓ Endpoint de métricas funcionando perfeitamente!');
                
                try {
                    const metrics = JSON.parse(data);
                    console.log('\n=== RESUMO DAS MÉTRICAS ===');
                    console.log('Total de usuários:', metrics.overview?.totalUsers || 'N/A');
                    console.log('Total de questões:', metrics.overview?.totalQuestions || 'N/A');
                    console.log('Total de categorias:', metrics.overview?.totalCategories || 'N/A');
                    console.log('Usuários ativos:', metrics.overview?.activeUsers || 'N/A');
                    console.log('Questões por dificuldade:', metrics.questionStats?.byDifficulty?.length || 0, 'níveis');
                    console.log('Questões por categoria:', metrics.questionStats?.byCategory?.length || 0, 'categorias');
                    console.log('\n✓ Todas as métricas foram calculadas com sucesso!');
                } catch (err) {
                    console.log('Erro ao fazer parse das métricas:', err.message);
                    console.log('Primeiros 500 caracteres:', data.substring(0, 500));
                }
            } else if (res.statusCode === 500) {
                console.log('✗ Ainda há erro 500 no endpoint de métricas:');
                console.log(data);
            } else {
                console.log('✗ Status inesperado:', res.statusCode);
                console.log(data);
            }
        });
    });
    
    req.on('error', (err) => {
        console.error('Erro na requisição de métricas:', err.message);
    });
    
    req.end();
}

// Iniciar o teste
loginAndTestMetrics();
