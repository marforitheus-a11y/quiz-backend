const https = require('https');

function testCategoryFix() {
    console.log('🔄 Testando correção de categorias...');
    
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
                    
                    // Aguardar deploy e executar correção
                    console.log('⏳ Aguardando deploy (60 segundos)...');
                    setTimeout(() => {
                        fixCategories(response.token);
                    }, 60000); // 60 segundos
                } catch (err) {
                    console.log('❌ Erro no parse do login:', err.message);
                }
            } else {
                console.log('❌ Erro no login:', data);
            }
        });
    });
    
    req.on('error', (err) => {
        console.error('❌ Erro na requisição de login:', err.message);
    });
    
    req.write(loginData);
    req.end();
}

function fixCategories(token) {
    console.log('\n🛠️ EXECUTANDO CORREÇÃO DE CATEGORIAS...');
    
    const options = {
        hostname: 'quiz-api-z4ri.onrender.com',
        path: '/admin/fix-categories-advanced',
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
            console.log('📊 Status da correção:', res.statusCode);
            
            if (res.statusCode === 200) {
                try {
                    const result = JSON.parse(data);
                    console.log('\n🎉 CORREÇÃO CONCLUÍDA!');
                    console.log('✅ Mensagem:', result.message);
                    console.log('📈 Questões reclassificadas:', result.reclassified);
                    
                    if (result.byCategory) {
                        console.log('\n📊 RECLASSIFICAÇÃO POR CATEGORIA:');
                        Object.entries(result.byCategory).forEach(([cat, count]) => {
                            console.log(`  📁 ${cat}: ${count} questões`);
                        });
                    }
                    
                    if (result.finalStats) {
                        console.log('\n📈 ESTATÍSTICAS FINAIS:');
                        result.finalStats.forEach(stat => {
                            console.log(`  📚 ${stat.category}: ${stat.count} questões`);
                        });
                    }
                    
                    // Aguardar um pouco e testar as métricas
                    console.log('\n⏳ Aguardando 30 segundos para testar métricas...');
                    setTimeout(() => {
                        testMetricsAfterFix(token);
                    }, 30000);
                    
                } catch (err) {
                    console.log('❌ Erro ao parse resultado:', err.message);
                    console.log('Response (primeiros 500 chars):', data.substring(0, 500));
                }
            } else {
                console.log('❌ Erro na correção:', res.statusCode, data);
            }
        });
    });
    
    req.on('error', (err) => {
        console.error('❌ Erro na requisição de correção:', err.message);
    });
    
    req.end();
}

function testMetricsAfterFix(token) {
    console.log('\n📊 TESTANDO MÉTRICAS APÓS CORREÇÃO...');
    
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
                    
                    console.log('\n🎯 VERIFICAÇÃO DAS CATEGORIAS:');
                    
                    if (metrics.questionStats?.byCategory?.length > 0) {
                        let semCategoriaCount = 0;
                        let totalOtherCategories = 0;
                        
                        metrics.questionStats.byCategory.forEach(cat => {
                            if (cat.category === 'Sem Categoria') {
                                semCategoriaCount = cat.count;
                                console.log(`  ⚠️ ${cat.category}: ${cat.count} questões`);
                            } else {
                                totalOtherCategories += cat.count;
                                console.log(`  ✅ ${cat.category}: ${cat.count} questões`);
                            }
                        });
                        
                        console.log(`\n📊 RESUMO:`);
                        console.log(`  🎯 Questões categorizadas: ${totalOtherCategories}`);
                        console.log(`  ⚠️ Ainda sem categoria: ${semCategoriaCount}`);
                        
                        if (semCategoriaCount < 1000) {
                            console.log('  🎉 SUCESSO! Maioria das questões foram categorizadas!');
                        } else {
                            console.log('  ⚠️ ATENÇÃO: Ainda há muitas questões sem categoria.');
                        }
                        
                    } else {
                        console.log('❌ Nenhuma categoria encontrada nas métricas');
                    }
                    
                } catch (err) {
                    console.log('❌ Erro ao parse métricas:', err.message);
                }
            } else {
                console.log('❌ Erro ao buscar métricas:', res.statusCode);
            }
        });
    });
    
    req.on('error', (err) => {
        console.error('❌ Erro na requisição de métricas:', err.message);
    });
    
    req.end();
}

// Iniciar teste
testCategoryFix();
