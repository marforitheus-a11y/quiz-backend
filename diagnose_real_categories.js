const https = require('https');

function diagnoseCategoriesAndFix() {
    console.log('🔍 INICIANDO DIAGNÓSTICO DE CATEGORIAS...');
    console.log('⏳ Aguardando 30 segundos para o deploy...');
    
    setTimeout(() => {
        executeDiagnosis();
    }, 30000); // 30 segundos
}

function executeDiagnosis() {
    console.log('\n🛠️ EXECUTANDO DIAGNÓSTICO...');
    
    const options = {
        hostname: 'quiz-api-z4ri.onrender.com',
        path: '/public/diagnose-categories',
        method: 'GET'
    };
    
    const req = https.request(options, (res) => {
        let data = '';
        
        res.on('data', (chunk) => {
            data += chunk;
        });
        
        res.on('end', () => {
            console.log('📊 Status do diagnóstico:', res.statusCode);
            
            if (res.statusCode === 200) {
                try {
                    const result = JSON.parse(data);
                    analyzeDiagnosis(result);
                } catch (err) {
                    console.log('❌ Erro ao parse diagnóstico:', err.message);
                    console.log('Response (primeiros 1000 chars):', data.substring(0, 1000));
                }
            } else {
                console.log('❌ Erro no diagnóstico:', res.statusCode);
                console.log('Response:', data.substring(0, 500));
            }
        });
    });
    
    req.on('error', (err) => {
        console.error('❌ Erro na requisição de diagnóstico:', err.message);
    });
    
    req.end();
}

function analyzeDiagnosis(result) {
    console.log('\n📈 RESULTADO DO DIAGNÓSTICO:');
    console.log(`📊 Total de questões: ${result.totalQuestions}`);
    console.log(`❓ Questões sem categoria: ${result.questionsWithoutCategory}`);
    console.log(`📂 Total de categorias: ${result.totalCategories}`);
    
    console.log('\n📂 TODAS AS CATEGORIAS NO SISTEMA:');
    result.categories.forEach(cat => {
        console.log(`  ID: ${cat.id} - Nome: "${cat.name}"`);
    });
    
    console.log('\n📊 DISTRIBUIÇÃO ATUAL:');
    result.distribution.forEach(cat => {
        console.log(`  📁 ${cat.name}: ${cat.count} questões (ID: ${cat.id})`);
    });
    
    // Identificar categorias que podem ser originais vs criadas
    console.log('\n🔍 ANÁLISE DAS CATEGORIAS:');
    
    const possibleOriginalCategories = result.categories.filter(cat => 
        cat.name === 'Sem Categoria' || 
        cat.id <= 10 // IDs baixos provavelmente são originais
    );
    
    const possibleCreatedCategories = result.categories.filter(cat => 
        cat.name !== 'Sem Categoria' && 
        cat.id > 10 && // IDs altos provavelmente foram criados
        ['Português', 'Matemática', 'História', 'Geografia', 'Ciências', 'Física', 'Química', 'Biologia', 'Literatura', 'Inglês'].includes(cat.name)
    );
    
    console.log('\n🎯 CATEGORIAS POSSIVELMENTE ORIGINAIS:');
    possibleOriginalCategories.forEach(cat => {
        const dist = result.distribution.find(d => d.id === cat.id);
        console.log(`  ✅ ID: ${cat.id} - "${cat.name}" (${dist ? dist.count : 0} questões)`);
    });
    
    console.log('\n⚠️ CATEGORIAS POSSIVELMENTE CRIADAS PELO SCRIPT:');
    possibleCreatedCategories.forEach(cat => {
        const dist = result.distribution.find(d => d.id === cat.id);
        console.log(`  ❌ ID: ${cat.id} - "${cat.name}" (${dist ? dist.count : 0} questões)`);
    });
    
    // Buscar categorias com questões
    const categoriesWithQuestions = result.distribution.filter(cat => cat.count > 0);
    const categoriesWithoutQuestions = result.distribution.filter(cat => cat.count === 0);
    
    console.log('\n📈 CATEGORIAS COM QUESTÕES:');
    categoriesWithQuestions.forEach(cat => {
        console.log(`  📁 ${cat.name}: ${cat.count} questões`);
    });
    
    console.log('\n📭 CATEGORIAS VAZIAS:');
    if (categoriesWithoutQuestions.length > 0) {
        categoriesWithoutQuestions.forEach(cat => {
            console.log(`  🗑️ ${cat.name}: 0 questões (pode ser removida)`);
        });
    } else {
        console.log('  ✅ Nenhuma categoria vazia');
    }
    
    // Propor solução
    console.log('\n💡 PLANO DE CORREÇÃO:');
    
    if (possibleCreatedCategories.length > 0) {
        console.log('1. 🔄 CONSOLIDAR QUESTÕES:');
        console.log('   - Mover todas as questões para "Sem Categoria"');
        console.log('   - Remover categorias criadas incorretamente');
        console.log('   - Usar apenas categorias originais do sistema');
        
        console.log('\n2. 📊 RECLASSIFICAÇÃO COM CATEGORIAS REAIS:');
        console.log('   - Identificar quais categorias realmente existiam no sistema original');
        console.log('   - Classificar questões usando apenas essas categorias');
        
        console.log('\n3. 🎯 MÉTRICAS REAIS:');
        console.log('   - Dashboard mostrará apenas dados verdadeiros');
        console.log('   - Sem categorias artificiais');
        
        console.log('\n❓ PERGUNTAS PARA O ADMINISTRADOR:');
        console.log('1. Quais categorias realmente existiam no sistema original?');
        console.log('2. Devo manter apenas "Sem Categoria" e as categorias originais?');
        console.log('3. Devo remover todas as categorias criadas pelo script de emergência?');
        
        console.log('\n🚀 Quer que eu execute a correção usando apenas categorias originais?');
        console.log('Digite "sim" para continuar ou "não" para parar.');
        
    } else {
        console.log('✅ Todas as categorias parecem ser originais do sistema');
        console.log('✅ Nenhuma ação necessária');
    }
}

console.log('🚀 INICIANDO DIAGNÓSTICO DE CATEGORIAS REAIS...');
console.log('📋 Este script vai:');
console.log('1. Verificar todas as categorias no sistema');
console.log('2. Identificar quais são originais vs criadas pelo script');
console.log('3. Propor correção usando apenas categorias reais');

diagnoseCategoriesAndFix();
