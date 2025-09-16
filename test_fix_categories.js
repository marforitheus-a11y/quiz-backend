const https = require('https');

function fixCategoriesInProduction() {
    console.log('Corrigindo categorias na produção...');
    
    // Fazer login primeiro
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
            if (res.statusCode === 200) {
                try {
                    const response = JSON.parse(data);
                    console.log('✓ Login bem-sucedido!');
                    
                    // Criar endpoint para corrigir categorias
                    createFixCategoriesEndpoint(response.token);
                } catch (err) {
                    console.log('Erro no parse do login:', err.message);
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

function createFixCategoriesEndpoint(token) {
    console.log('\nChamando endpoint para corrigir categorias...');
    
    const options = {
        hostname: 'quiz-api-z4ri.onrender.com',
        path: '/admin/fix-categories',
        method: 'POST',
        headers: {
            'Authorization': `Bearer ${token}`,
            'Content-Type': 'application/json'
        }
    };
    
    const req = https.request(options, (res) => {
        let data = '';
        
        res.on('data', (chunk) => {
            data += chunk;
        });
        
        res.on('end', () => {
            console.log('Fix Categories Status:', res.statusCode);
            
            if (res.statusCode === 200) {
                try {
                    const response = JSON.parse(data);
                    console.log('✓ Categorias corrigidas com sucesso!');
                    console.log('Resultado:', response);
                    
                    // Testar as métricas novamente
                    testMetricsAfterFix(token);
                } catch (err) {
                    console.log('Erro ao parse resposta:', err.message);
                    console.log('Response:', data);
                }
            } else if (res.statusCode === 404) {
                console.log('✗ Endpoint /admin/fix-categories não existe ainda');
                console.log('Precisa fazer deploy do código atualizado');
            } else {
                console.log('✗ Erro ao corrigir categorias:', data);
            }
        });
    });
    
    req.on('error', (err) => {
        console.error('Erro na requisição:', err.message);
    });
    
    req.end();
}

function testMetricsAfterFix(token) {
    console.log('\n=== TESTANDO MÉTRICAS APÓS CORREÇÃO ===');
    
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
            if (res.statusCode === 200) {
                try {
                    const metrics = JSON.parse(data);
                    console.log('✓ Métricas atualizadas:');
                    console.log('Questões por categoria:');
                    
                    if (metrics.questionStats && metrics.questionStats.byCategory) {
                        metrics.questionStats.byCategory.forEach(cat => {
                            console.log(`  - ${cat.category}: ${cat.count} questões`);
                        });
                    } else {
                        console.log('  Nenhuma categoria encontrada');
                    }
                } catch (err) {
                    console.log('Erro ao parse métricas:', err.message);
                }
            } else {
                console.log('✗ Erro ao buscar métricas:', res.statusCode);
            }
        });
    });
    
    req.on('error', (err) => {
        console.error('Erro na requisição de métricas:', err.message);
    });
    
    req.end();
}

// Iniciar processo
fixCategoriesInProduction();
