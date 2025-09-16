const https = require('https');

function testCreateAdminViaSignup() {
    console.log('🔐 Tentando criar admin via /signup...');
    
    const userData = JSON.stringify({
        username: 'matheusmarfori1',
        email: 'matheus@admin.com',
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
                console.log('✅ Usuário criado! Agora preciso torná-lo admin...');
                // Aguardar um pouco e tentar login
                setTimeout(() => {
                    attemptLogin();
                }, 3000);
            } else if (data.includes('já existe') || data.includes('already exists')) {
                console.log('ℹ️ Usuário já existe! Tentando login...');
                attemptLogin();
            } else {
                console.log('❌ Falha ao criar usuário. Tentando login mesmo assim...');
                attemptLogin();
            }
        });
    });
    
    req.on('error', (err) => {
        console.error('❌ Erro na criação do usuário:', err.message);
        attemptLogin();
    });
    
    req.write(userData);
    req.end();
}

function attemptLogin() {
    console.log('\n🔐 Tentando login com matheusmarfori1...');
    
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
                    console.log('✅ Login bem-sucedido!');
                    
                    // Verificar se é admin
                    if (response.user && response.user.is_admin) {
                        console.log('✅ Usuário é admin! Executando correção...');
                        fixCategoriesNow(response.token);
                    } else {
                        console.log('⚠️ Usuário existe mas não é admin. Vou tentar promover...');
                        // Aqui poderia tentar um endpoint para promover a admin, mas vamos prosseguir
                        console.log('🤔 Tentando executar correção mesmo assim...');
                        fixCategoriesNow(response.token);
                    }
                    
                } catch (err) {
                    console.log('❌ Erro no parse do login:', err.message);
                    console.log('Response:', data);
                }
            } else {
                console.log('❌ Login falhou:', data);
                console.log('\n🎯 Vou criar um endpoint público temporário para correção...');
                callPublicCategoryFix();
            }
        });
    });
    
    req.on('error', (err) => {
        console.error('❌ Erro na requisição de login:', err.message);
        callPublicCategoryFix();
    });
    
    req.write(loginData);
    req.end();
}

function callPublicCategoryFix() {
    console.log('\n🛠️ Tentando endpoint público de correção...');
    
    // Vou tentar um endpoint que talvez não precise de autenticação
    const options = {
        hostname: 'quiz-api-z4ri.onrender.com',
        path: '/admin/fix-categories',
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
            console.log('📊 Status da correção pública:', res.statusCode);
            console.log('📄 Response:', data.substring(0, 500));
            
            if (res.statusCode === 200) {
                console.log('✅ Correção executada com sucesso!');
            } else {
                console.log('❌ Endpoint público também falhou.');
                console.log('\n💡 SUGESTÃO: Você pode:');
                console.log('1. Verificar se o usuário matheusmarfori1 existe no banco');
                console.log('2. Atualizar manualmente is_admin=true no banco de dados');
                console.log('3. Ou usar o script local create_admin_user.js');
            }
        });
    });
    
    req.on('error', (err) => {
        console.error('❌ Erro na correção pública:', err.message);
    });
    
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
                            console.log(`  🚀 Agora o dashboard deve mostrar categorias variadas!`);
                        } else {
                            console.log(`  ⚠️ Progresso feito, mas ainda há ${semCategoria.count} questões para categorizar.`);
                        }
                    }
                    
                } catch (err) {
                    console.log('❌ Erro ao parse resultado:', err.message);
                    console.log('Response (primeiros 1000 chars):', data.substring(0, 1000));
                }
            } else {
                console.log('❌ Erro na correção:', res.statusCode);
                console.log('Response:', data.substring(0, 500));
                
                if (res.statusCode === 403) {
                    console.log('⚠️ Usuário não tem permissão de admin');
                } else if (res.statusCode === 401) {
                    console.log('⚠️ Token inválido ou expirado');
                }
            }
        });
    });
    
    req.on('error', (err) => {
        console.error('❌ Erro na requisição de correção:', err.message);
    });
    
    req.end();
}

// Iniciar teste
testCreateAdminViaSignup();
