const https = require('https');

function testImprovedMetrics() {
    console.log('Testando métricas melhoradas após correções...');
    
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
                    
                    // Aguardar um pouco para o deploy e testar métricas
                    console.log('Aguardando deploy do backend...');
                    setTimeout(() => {
                        testMetricsEndpoint(response.token);
                    }, 30000); // 30 segundos
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

function testMetricsEndpoint(token) {
    console.log('\n=== TESTANDO MÉTRICAS MELHORADAS ===');
    
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
                try {
                    const metrics = JSON.parse(data);
                    console.log('🎉 MÉTRICAS OBTIDAS COM SUCESSO!\n');
                    
                    // Verificar overview
                    console.log('=== OVERVIEW ===');
                    console.log('✓ Total de usuários:', metrics.overview?.totalUsers || 'N/A');
                    console.log('✓ Total de questões:', metrics.overview?.totalQuestions || 'N/A');
                    console.log('✓ Total de categorias:', metrics.overview?.totalCategories || 'N/A');
                    console.log('✓ Usuários ativos:', metrics.overview?.activeUsers || 'N/A');
                    console.log('✓ Taxa de crescimento:', metrics.overview?.userGrowthRate || 'N/A', '%');
                    
                    // Verificar questões por categoria
                    console.log('\n=== QUESTÕES POR CATEGORIA ===');
                    if (metrics.questionStats?.byCategory?.length > 0) {
                        console.log('✅ CORRIGIDO: Categorias encontradas!');
                        metrics.questionStats.byCategory.forEach(cat => {
                            console.log(`  📁 ${cat.category}: ${cat.count} questões`);
                        });
                    } else {
                        console.log('❌ Ainda sem categorias');
                    }
                    
                    // Verificar questões por dificuldade
                    console.log('\n=== QUESTÕES POR DIFICULDADE ===');
                    if (metrics.questionStats?.byDifficulty?.length > 0) {
                        metrics.questionStats.byDifficulty.forEach(diff => {
                            console.log(`  🎯 ${diff.difficulty}: ${diff.count} questões`);
                        });
                    } else {
                        console.log('❌ Sem dados de dificuldade');
                    }
                    
                    // Verificar performance
                    console.log('\n=== PERFORMANCE GERAL ===');
                    if (metrics.performance) {
                        const perf = metrics.performance;
                        if (perf.totalSessions > 0) {
                            console.log('✅ CORRIGIDO: Performance com dados!');
                            console.log(`  📊 Sessões totais: ${perf.totalSessions}`);
                            console.log(`  📈 Score médio: ${perf.avgScore}`);
                            console.log(`  📉 Score mínimo: ${perf.minScore}`);
                            console.log(`  📈 Score máximo: ${perf.maxScore}`);
                        } else {
                            console.log('❌ Performance ainda zerada');
                        }
                    }
                    
                    // Verificar top usuários
                    console.log('\n=== TOP 5 USUÁRIOS ===');
                    if (metrics.activity?.topUsers?.length > 0) {
                        console.log('✅ CORRIGIDO: Top usuários encontrados!');
                        metrics.activity.topUsers.forEach((user, i) => {
                            console.log(`  ${i + 1}. 👤 ${user.username} - ${user.quizCount} quizzes`);
                        });
                    } else {
                        console.log('❌ Top usuários ainda vazio');
                    }
                    
                    // Verificar atividade por dia
                    console.log('\n=== ATIVIDADE POR DIA ===');
                    if (metrics.activity?.sessionsPerDay?.length > 0) {
                        console.log('✅ CORRIGIDO: Sessões por dia encontradas!');
                        metrics.activity.sessionsPerDay.forEach(day => {
                            console.log(`  📅 ${day.date}: ${day.count} sessões`);
                        });
                    } else {
                        console.log('❌ Sessões por dia ainda vazio');
                    }
                    
                    console.log('\n🏁 RESUMO DOS PROBLEMAS:');
                    const problems = [];
                    
                    if (!metrics.questionStats?.byCategory?.length || 
                        (metrics.questionStats.byCategory.length === 1 && 
                         metrics.questionStats.byCategory[0].category === 'Sem Categoria')) {
                        problems.push('❌ Categorias ainda não corrigidas');
                    } else {
                        console.log('✅ Categorias: CORRIGIDO');
                    }
                    
                    if (!metrics.performance?.totalSessions || metrics.performance.totalSessions === 0) {
                        problems.push('❌ Performance ainda zerada');
                    } else {
                        console.log('✅ Performance: CORRIGIDO');
                    }
                    
                    if (!metrics.overview?.activeUsers || metrics.overview.activeUsers === 0) {
                        problems.push('❌ Usuários ativos ainda zero');
                    } else {
                        console.log('✅ Usuários ativos: CORRIGIDO');
                    }
                    
                    if (!metrics.activity?.topUsers?.length) {
                        problems.push('❌ Top usuários ainda vazio');
                    } else {
                        console.log('✅ Top usuários: CORRIGIDO');
                    }
                    
                    if (problems.length === 0) {
                        console.log('\n🎉 TODOS OS PROBLEMAS FORAM CORRIGIDOS!');
                    } else {
                        console.log('\n⚠️ Problemas restantes:');
                        problems.forEach(problem => console.log(problem));
                        console.log('\nPode levar alguns minutos para o deploy refletir todas as mudanças.');
                    }
                    
                } catch (err) {
                    console.log('Erro ao parse métricas:', err.message);
                    console.log('Response (primeiros 500 chars):', data.substring(0, 500));
                }
            } else {
                console.log('✗ Erro ao buscar métricas:', res.statusCode, data);
            }
        });
    });
    
    req.on('error', (err) => {
        console.error('Erro na requisição de métricas:', err.message);
    });
    
    req.end();
}

// Iniciar teste
testImprovedMetrics();
