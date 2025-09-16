const https = require('https');

function checkExistingCategories() {
    console.log('🔍 VERIFICANDO CATEGORIAS EXISTENTES...');
    
    const options = {
        hostname: 'quiz-api-z4ri.onrender.com',
        path: '/categories',
        method: 'GET',
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
            console.log('📊 Status das categorias:', res.statusCode);
            
            if (res.statusCode === 200) {
                try {
                    const categories = JSON.parse(data);
                    console.log('\n📂 CATEGORIAS EXISTENTES NO SISTEMA:');
                    
                    if (Array.isArray(categories)) {
                        categories.forEach((cat, index) => {
                            console.log(`  ${index + 1}. ID: ${cat.id} - Nome: "${cat.name}"`);
                        });
                        
                        // Agora verificar quantas questões tem em cada
                        console.log('\n🔍 Verificando distribuição atual...');
                        checkCurrentDistribution();
                    } else {
                        console.log('Formato inesperado:', categories);
                    }
                    
                } catch (err) {
                    console.log('❌ Erro ao parse categorias:', err.message);
                    console.log('Response:', data);
                }
            } else {
                console.log('❌ Erro ao buscar categorias:', res.statusCode);
                console.log('Response:', data);
            }
        });
    });
    
    req.on('error', (err) => {
        console.error('❌ Erro na requisição:', err.message);
    });
    
    req.end();
}

function checkCurrentDistribution() {
    console.log('\n📊 VERIFICANDO DISTRIBUIÇÃO ATUAL DAS QUESTÕES...');
    
    // Fazer login para acessar métricas
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
            if (res.statusCode === 200) {
                try {
                    const response = JSON.parse(data);
                    console.log('✅ Login bem-sucedido!');
                    getMetrics(response.token);
                } catch (err) {
                    console.log('❌ Erro no login:', err.message);
                    tryWithoutAuth();
                }
            } else {
                console.log('❌ Login falhou, tentando sem autenticação...');
                tryWithoutAuth();
            }
        });
    });
    
    req.on('error', (err) => {
        console.error('❌ Erro no login:', err.message);
        tryWithoutAuth();
    });
    
    req.write(loginData);
    req.end();
}

function tryWithoutAuth() {
    console.log('\n📊 Tentando buscar métricas sem autenticação...');
    
    const options = {
        hostname: 'quiz-api-z4ri.onrender.com',
        path: '/admin/dashboard/metrics',
        method: 'GET'
    };
    
    const req = https.request(options, (res) => {
        let data = '';
        
        res.on('data', (chunk) => {
            data += chunk;
        });
        
        res.on('end', () => {
            console.log('📊 Status das métricas:', res.statusCode);
            
            if (res.statusCode === 200) {
                try {
                    const metrics = JSON.parse(data);
                    analyzeCurrentState(metrics);
                } catch (err) {
                    console.log('❌ Erro ao parse métricas:', err.message);
                }
            } else {
                console.log('❌ Não foi possível acessar métricas:', res.statusCode);
                console.log('Sugestão: Criar um endpoint público para verificar distribuição');
            }
        });
    });
    
    req.on('error', (err) => {
        console.error('❌ Erro na requisição de métricas:', err.message);
    });
    
    req.end();
}

function getMetrics(token) {
    console.log('\n📊 Buscando métricas com autenticação...');
    
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
                    analyzeCurrentState(metrics);
                } catch (err) {
                    console.log('❌ Erro ao parse métricas:', err.message);
                }
            } else {
                console.log('❌ Erro nas métricas:', res.statusCode);
            }
        });
    });
    
    req.on('error', (err) => {
        console.error('❌ Erro na requisição de métricas:', err.message);
    });
    
    req.end();
}

function analyzeCurrentState(metrics) {
    console.log('\n📈 ANÁLISE DO ESTADO ATUAL:');
    
    if (metrics.questionStats?.byCategory?.length > 0) {
        console.log('\n📊 DISTRIBUIÇÃO ATUAL POR CATEGORIA:');
        let totalQuestionsInCategories = 0;
        
        metrics.questionStats.byCategory.forEach(cat => {
            console.log(`  📁 ${cat.category}: ${cat.count} questões`);
            totalQuestionsInCategories += cat.count;
        });
        
        console.log(`\n📊 Total de questões: ${totalQuestionsInCategories}`);
        
        // Identificar categorias problemáticas
        const problematicCategories = metrics.questionStats.byCategory.filter(cat => 
            !['Sem Categoria'].includes(cat.category) && 
            !cat.category.match(/^(Português|Matemática|História|Geografia|Ciências|Física|Química|Biologia)$/i)
        );
        
        if (problematicCategories.length > 0) {
            console.log('\n⚠️ CATEGORIAS CRIADAS INCORRETAMENTE:');
            problematicCategories.forEach(cat => {
                console.log(`  ❌ ${cat.category}: ${cat.count} questões`);
            });
            
            console.log('\n💡 SOLUÇÃO NECESSÁRIA:');
            console.log('1. Identificar categorias legítimas originais');
            console.log('2. Reclassificar questões usando apenas categorias válidas');
            console.log('3. Remover categorias criadas incorretamente');
        }
        
        // Verificar "Sem Categoria"
        const semCategoria = metrics.questionStats.byCategory.find(cat => cat.category === 'Sem Categoria');
        if (semCategoria) {
            console.log(`\n⚠️ Ainda há ${semCategoria.count} questões em "Sem Categoria"`);
        } else {
            console.log('\n✅ Não há questões em "Sem Categoria"');
        }
        
    } else {
        console.log('❌ Nenhuma categoria encontrada nas métricas');
    }
    
    console.log('\n🎯 PRÓXIMOS PASSOS:');
    console.log('1. Verificar quais eram as categorias originais no sistema');
    console.log('2. Criar script para corrigir usando apenas categorias válidas');
    console.log('3. Remover categorias incorretamente criadas');
}

// Iniciar verificação
checkExistingCategories();
