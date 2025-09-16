const https = require('https');

function testWithOfficialAdmin() {
    console.log('🔐 Testando com credenciais oficiais do administrador...');
    
    const loginData = JSON.stringify({
        username: 'matheusmarfori1',
        password: 'Realmadry19*'
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
            console.log('📊 Status do login:', res.statusCode);
            
            if (res.statusCode === 200) {
                try {
                    const response = JSON.parse(data);
                    console.log('✅ Login bem-sucedido com matheusmarfori1!');
                    console.log('🎫 Token obtido');
                    
                    // Executar correção de categorias imediatamente
                    fixCategoriesNow(response.token);
                    
                } catch (err) {
                    console.log('❌ Erro no parse do login:', err.message);
                    console.log('Response:', data);
                }
            } else {
                console.log('❌ Login falhou:', data);
                console.log('Vou tentar criar o usuário admin...');
                createAdminUser();
            }
        });
    });
    
    req.on('error', (err) => {
        console.error('❌ Erro na requisição de login:', err.message);
    });
    
    req.write(loginData);
    req.end();
}

function createAdminUser() {
    console.log('\n👤 Tentando criar usuário admin via endpoint...');
    
    const userData = JSON.stringify({
        username: 'matheusmarfori1',
        email: 'matheus@admin.com',
        password: 'Realmadry19*',
        isAdmin: true
    });
    
    const options = {
        hostname: 'quiz-api-z4ri.onrender.com',
        path: '/register',
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'Content-Length': Buffer.byteLength(userData)
        }
    };
    
    const req = https.request(options, (res) => {
        let data = '';
        
        res.on('data', (chunk) => {
            data += chunk;
        });
        
        res.on('end', () => {
            console.log('📊 Status do registro:', res.statusCode);
            console.log('📄 Response:', data);
            
            if (res.statusCode === 201 || res.statusCode === 200) {
                console.log('✅ Usuário criado! Tentando login novamente...');
                setTimeout(() => {
                    testWithOfficialAdmin();
                }, 3000);
            } else {
                console.log('❌ Falha ao criar usuário');
            }
        });
    });
    
    req.on('error', (err) => {
        console.error('❌ Erro na criação do usuário:', err.message);
    });
    
    req.write(userData);
    req.end();
}

function fixCategoriesNow(token) {
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
                    console.log('\n🎉 CORREÇÃO DE CATEGORIAS CONCLUÍDA!');
                    console.log('✅ Mensagem:', result.message);
                    console.log('📈 Questões reclassificadas:', result.reclassified);
                    
                    if (result.byCategory && Object.keys(result.byCategory).length > 0) {
                        console.log('\n📊 RECLASSIFICAÇÃO POR CATEGORIA:');
                        Object.entries(result.byCategory).forEach(([cat, count]) => {
                            console.log(`  📁 ${cat}: ${count} questões`);
                        });
                    }
                    
                    if (result.finalStats && result.finalStats.length > 0) {
                        console.log('\n📈 ESTATÍSTICAS FINAIS:');
                        result.finalStats.forEach(stat => {
                            console.log(`  📚 ${stat.category}: ${stat.count} questões`);
                        });
                        
                        // Análise detalhada
                        const semCategoria = result.finalStats.find(s => s.category === 'Sem Categoria');
                        const outrasCategs = result.finalStats.filter(s => s.category !== 'Sem Categoria');
                        const totalOutras = outrasCategs.reduce((sum, s) => sum + s.count, 0);
                        
                        console.log(`\n🎯 ANÁLISE FINAL:`);
                        console.log(`  ✅ Questões categorizadas: ${totalOutras}`);
                        console.log(`  ⚠️ Ainda sem categoria: ${semCategoria ? semCategoria.count : 0}`);
                        
                        if (!semCategoria || semCategoria.count < 500) {
                            console.log(`  🎉 EXCELENTE! Problema das categorias resolvido!`);
                        } else if (semCategoria.count < 1500) {
                            console.log(`  ✅ BOM PROGRESSO! Reduziu significativamente questões sem categoria.`);
                        } else {
                            console.log(`  ⚠️ ATENÇÃO: Ainda há ${semCategoria.count} questões para categorizar.`);
                        }
                    }
                    
                    // Aguardar e testar métricas
                    console.log('\n⏳ Aguardando 20 segundos para testar métricas...');
                    setTimeout(() => {
                        testMetricsAfterFix(token);
                    }, 20000);
                    
                } catch (err) {
                    console.log('❌ Erro ao parse resultado:', err.message);
                    console.log('Response (primeiros 1000 chars):', data.substring(0, 1000));
                }
            } else {
                console.log('❌ Erro na correção:', res.statusCode);
                console.log('Response:', data.substring(0, 500));
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
                    
                    console.log('\n🎯 VERIFICAÇÃO FINAL DAS CATEGORIAS:');
                    
                    if (metrics.questionStats?.byCategory?.length > 0) {
                        let semCategoriaCount = 0;
                        let totalOutras = 0;
                        let categoriasEncontradas = [];
                        
                        metrics.questionStats.byCategory.forEach(cat => {
                            if (cat.category === 'Sem Categoria') {
                                semCategoriaCount = cat.count;
                                console.log(`  ⚠️ ${cat.category}: ${cat.count} questões`);
                            } else {
                                totalOutras += cat.count;
                                categoriasEncontradas.push(`${cat.category} (${cat.count})`);
                                console.log(`  ✅ ${cat.category}: ${cat.count} questões`);
                            }
                        });
                        
                        console.log(`\n📊 RESUMO FINAL:`);
                        console.log(`  🎯 Total de categorias diferentes: ${categoriasEncontradas.length}`);
                        console.log(`  ✅ Questões categorizadas: ${totalOutras}`);
                        console.log(`  ⚠️ Ainda sem categoria: ${semCategoriaCount}`);
                        
                        const porcentagemCategorizada = ((totalOutras / (totalOutras + semCategoriaCount)) * 100).toFixed(1);
                        console.log(`  📈 Porcentagem categorizada: ${porcentagemCategorizada}%`);
                        
                        if (semCategoriaCount < 1000) {
                            console.log('\n🎉 PROBLEMA RESOLVIDO! Dashboard agora mostra categorias variadas!');
                        } else if (semCategoriaCount < 2000) {
                            console.log('\n✅ PROGRESSO SIGNIFICATIVO! Muito melhor que antes!');
                        } else {
                            console.log('\n⚠️ Ainda precisa de mais melhorias na categorização.');
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
testWithOfficialAdmin();
