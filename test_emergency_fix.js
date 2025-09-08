const https = require('https');

function testEmergencyEndpoint() {
    console.log('🚨 TESTANDO ENDPOINT DE EMERGÊNCIA...');
    console.log('⏳ Aguardando 45 segundos para o deploy...');
    
    setTimeout(() => {
        executeEmergencyFix();
    }, 45000); // 45 segundos
}

function executeEmergencyFix() {
    console.log('\n🛠️ EXECUTANDO CORREÇÃO DE EMERGÊNCIA...');
    
    const options = {
        hostname: 'quiz-api-z4ri.onrender.com',
        path: '/public/fix-categories-emergency',
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        }
    };
    
    const req = https.request(options, (res) => {
        let data = '';
        
        res.on('data', (chunk) => {
            data += chunk;
        });
        
        res.on('end', () => {
            console.log('📊 Status da correção de emergência:', res.statusCode);
            
            if (res.statusCode === 200) {
                try {
                    const result = JSON.parse(data);
                    console.log('\n🎉 CORREÇÃO DE EMERGÊNCIA CONCLUÍDA!');
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
                        const totalGeral = totalOutras + (semCategoria ? semCategoria.count : 0);
                        
                        console.log(`\n🎯 ANÁLISE FINAL:`);
                        console.log(`  📊 Total de questões: ${totalGeral}`);
                        console.log(`  ✅ Questões categorizadas: ${totalOutras}`);
                        console.log(`  ⚠️ Ainda sem categoria: ${semCategoria ? semCategoria.count : 0}`);
                        
                        if (totalOutras > 0) {
                            const porcentagem = ((totalOutras / totalGeral) * 100).toFixed(1);
                            console.log(`  📈 Porcentagem categorizada: ${porcentagem}%`);
                        }
                        
                        if (!semCategoria || semCategoria.count < 1000) {
                            console.log(`\n🎉 EXCELENTE! Problema das categorias RESOLVIDO!`);
                            console.log(`🚀 O dashboard agora deve mostrar categorias variadas em vez de apenas "Sem Categoria"!`);
                            console.log(`📱 Recarregue a página do dashboard para ver as mudanças!`);
                        } else if (semCategoria.count < 2000) {
                            console.log(`\n✅ BOM PROGRESSO! Redução significativa de questões sem categoria.`);
                            console.log(`📊 De 2668 questões "Sem Categoria" para ${semCategoria.count}!`);
                        } else {
                            console.log(`\n⚠️ Algum progresso feito, mas ainda há ${semCategoria.count} questões para categorizar.`);
                        }
                        
                        // Agora testar se vai criar usuário admin
                        console.log('\n👤 Agora vou tentar criar seu usuário admin...');
                        setTimeout(() => {
                            createAdminUser();
                        }, 5000);
                    }
                    
                } catch (err) {
                    console.log('❌ Erro ao parse resultado:', err.message);
                    console.log('Response (primeiros 1000 chars):', data.substring(0, 1000));
                }
            } else {
                console.log('❌ Erro na correção de emergência:', res.statusCode);
                console.log('Response:', data.substring(0, 500));
                
                if (res.statusCode === 404) {
                    console.log('⚠️ Endpoint ainda não está disponível. Aguardando mais um pouco...');
                    setTimeout(() => {
                        executeEmergencyFix();
                    }, 30000);
                }
            }
        });
    });
    
    req.on('error', (err) => {
        console.error('❌ Erro na requisição de correção de emergência:', err.message);
    });
    
    req.end();
}

function createAdminUser() {
    console.log('\n👤 CRIANDO USUÁRIO ADMIN...');
    
    const userData = JSON.stringify({
        name: 'Matheus Marfori',  // Agora incluindo o campo name
        email: 'matheus@admin.com',
        username: 'matheusmarfori1',
        password: 'Realmadry19*'
    });
    
    const options = {
        hostname: 'quiz-api-z4ri.onrender.com',
        path: '/signup',
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
            console.log('📊 Status do signup:', res.statusCode);
            console.log('📄 Response:', data);
            
            if (res.statusCode === 201 || res.statusCode === 200) {
                console.log('✅ Usuário criado com sucesso!');
                console.log('\n💡 PRÓXIMOS PASSOS:');
                console.log('1. Entre em contato com o administrador do sistema para:');
                console.log('   - Alterar is_admin=true para o usuário matheusmarfori1 no banco');
                console.log('2. Ou execute o script local create_admin_user.js');
                console.log('3. Recarregue o dashboard para ver as categorias corrigidas!');
            } else if (data.includes('já cadastrado') || data.includes('already exists')) {
                console.log('ℹ️ Usuário já existe!');
                console.log('\n💡 Para torná-lo admin:');
                console.log('1. Execute: UPDATE users SET is_admin=true WHERE username=\'matheusmarfori1\';');
                console.log('2. Ou use o script create_admin_user.js localmente');
            } else {
                console.log('❌ Erro na criação do usuário');
            }
        });
    });
    
    req.on('error', (err) => {
        console.error('❌ Erro na criação do usuário:', err.message);
    });
    
    req.write(userData);
    req.end();
}

console.log('🚀 INICIANDO CORREÇÃO DE EMERGÊNCIA DE CATEGORIAS...');
console.log('📋 Este script vai:');
console.log('1. Aguardar o deploy do endpoint público');
console.log('2. Executar correção automática de categorias');
console.log('3. Distribuir questões entre Português, Matemática, História, etc.');
console.log('4. Tentar criar seu usuário admin');

testEmergencyEndpoint();
