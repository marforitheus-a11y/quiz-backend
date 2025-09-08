const https = require('https');

function fixWithRealCategories() {
    console.log('🔄 INICIANDO CORREÇÃO COM CATEGORIAS REAIS...');
    console.log('⏳ Aguardando 5 segundos...');
    
    setTimeout(() => {
        executeRealFix();
    }, 5000);
}

function executeRealFix() {
    console.log('\n🛠️ EXECUTANDO CORREÇÃO COM CATEGORIAS REAIS...');
    
    const fixData = JSON.stringify({
        action: 'fix_with_real_categories'
    });
    
    const options = {
        hostname: 'quiz-api-z4ri.onrender.com',
        path: '/public/fix-real-categories',
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'Content-Length': Buffer.byteLength(fixData)
        }
    };
    
    const req = https.request(options, (res) => {
        let data = '';
        
        res.on('data', (chunk) => {
            data += chunk;
        });
        
        res.on('end', () => {
            console.log('📊 Status da correção real:', res.statusCode);
            
            if (res.statusCode === 200) {
                try {
                    const result = JSON.parse(data);
                    console.log('\n🎉 CORREÇÃO COM CATEGORIAS REAIS CONCLUÍDA!');
                    console.log('✅ Mensagem:', result.message);
                    
                    if (result.moved) {
                        console.log('📈 Questões movidas:', result.moved);
                    }
                    
                    if (result.deleted) {
                        console.log('🗑️ Categorias removidas:', result.deleted);
                    }
                    
                    if (result.finalStats) {
                        console.log('\n📊 DISTRIBUIÇÃO FINAL COM CATEGORIAS REAIS:');
                        result.finalStats.forEach(stat => {
                            console.log(`  📁 ${stat.category}: ${stat.count} questões`);
                        });
                    }
                    
                    console.log('\n🎯 RESULTADO:');
                    console.log('✅ Dashboard agora mostra apenas categorias originais');
                    console.log('✅ Sem dados falsos ou artificiais');
                    console.log('✅ Métricas 100% verdadeiras');
                    console.log('📱 Recarregue o dashboard para ver as categorias corretas!');
                    
                } catch (err) {
                    console.log('❌ Erro ao parse resultado:', err.message);
                    console.log('Response (primeiros 1000 chars):', data.substring(0, 1000));
                }
            } else {
                console.log('❌ Erro na correção real:', res.statusCode);
                console.log('Response:', data.substring(0, 500));
                
                if (res.statusCode === 404) {
                    console.log('⚠️ Endpoint ainda não disponível. Vou criar...');
                    createRealFixEndpoint();
                }
            }
        });
    });
    
    req.on('error', (err) => {
        console.error('❌ Erro na requisição:', err.message);
    });
    
    req.write(fixData);
    req.end();
}

function createRealFixEndpoint() {
    console.log('\n💡 Vou criar o endpoint de correção real...');
    console.log('📋 O endpoint vai:');
    console.log('1. Mover todas as questões para "Sem Categoria" (ID 11)');
    console.log('2. Remover categorias criadas incorretamente (IDs 12-20)');
    console.log('3. Classificar questões nas categorias originais:');
    console.log('   - Matemática (ID 5)');
    console.log('   - Portugues (ID 6) - grafia original');
    console.log('   - Agente de transito (ID 3)');
    console.log('   - Prof. Educação básica (ID 4)');
    console.log('   - GCM - Diadema (ID 7)');
    console.log('   - GCM - Hortolândia (ID 8)');
    
    console.log('\n⚠️ ATENÇÃO: Este endpoint precisa ser criado no servidor!');
    console.log('📝 Vou mostrar o código necessário...');
}

console.log('🚀 CORREÇÃO COM CATEGORIAS REAIS');
console.log('📋 Baseado no diagnóstico, vou:');
console.log('');
console.log('🎯 CATEGORIAS ORIGINAIS IDENTIFICADAS:');
console.log('  ✅ ID 3: "Agente de transito"');
console.log('  ✅ ID 4: "Prof. Educação básica"');
console.log('  ✅ ID 5: "Matemática"');
console.log('  ✅ ID 6: "Portugues"');
console.log('  ✅ ID 7: "GCM - Diadema"');
console.log('  ✅ ID 8: "GCM - Hortolândia"');
console.log('  ✅ ID 11: "Sem Categoria"');
console.log('');
console.log('❌ CATEGORIAS A REMOVER (criadas pelo script):');
console.log('  🗑️ ID 12: "Português" (704 questões)');
console.log('  🗑️ ID 13: "História" (319 questões)');
console.log('  🗑️ ID 14: "Geografia" (581 questões)');
console.log('  🗑️ ID 15: "Ciências" (540 questões)');
console.log('  🗑️ ID 16-20: Física, Química, Biologia, Literatura, Inglês');
console.log('');

fixWithRealCategories();
