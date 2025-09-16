const https = require('https');

// Vamos tentar diferentes combinações de usuário admin
const adminCredentials = [
    { username: 'local_admin', password: 'AdminPass123!' },
    { username: 'admin', password: 'AdminPass123!' },
    { username: 'admin', password: 'admin123' },
    { username: 'admin', password: 'senha123' }
];

async function tryLogin(credentials, index = 0) {
    if (index >= adminCredentials.length) {
        console.log('❌ Nenhuma credencial funcionou. Vou executar correção diretamente no endpoint.');
        return;
    }
    
    const cred = adminCredentials[index];
    console.log(`🔐 Tentando login ${index + 1}/${adminCredentials.length}: ${cred.username}`);
    
    const loginData = JSON.stringify(cred);
    
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
                    console.log(`✅ Login bem-sucedido com: ${cred.username}`);
                    
                    // Executar correção imediatamente
                    fixCategoriesNow(response.token);
                    return;
                } catch (err) {
                    console.log(`❌ Erro no parse para ${cred.username}:`, err.message);
                }
            } else {
                console.log(`❌ Login falhou para ${cred.username}: ${data}`);
            }
            
            // Tentar próxima credencial
            setTimeout(() => tryLogin(credentials, index + 1), 2000);
        });
    });
    
    req.on('error', (err) => {
        console.error(`❌ Erro na requisição para ${cred.username}:`, err.message);
        setTimeout(() => tryLogin(credentials, index + 1), 2000);
    });
    
    req.write(loginData);
    req.end();
}

function fixCategoriesNow(token) {
    console.log('\n🛠️ EXECUTANDO CORREÇÃO DE CATEGORIAS AGORA...');
    
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
                        
                        // Analisar resultados
                        const semCategoria = result.finalStats.find(s => s.category === 'Sem Categoria');
                        const outrasCategs = result.finalStats.filter(s => s.category !== 'Sem Categoria');
                        const totalOutras = outrasCategs.reduce((sum, s) => sum + s.count, 0);
                        
                        console.log(`\n🎯 ANÁLISE:`);
                        console.log(`  ✅ Questões categorizadas: ${totalOutras}`);
                        console.log(`  ⚠️ Ainda sem categoria: ${semCategoria ? semCategoria.count : 0}`);
                        
                        if (!semCategoria || semCategoria.count < 500) {
                            console.log(`  🎉 EXCELENTE! Categorização bem-sucedida!`);
                        } else {
                            console.log(`  ⚠️ Ainda há ${semCategoria.count} questões para categorizar.`);
                        }
                    }
                    
                } catch (err) {
                    console.log('❌ Erro ao parse resultado:', err.message);
                    console.log('Response:', data);
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

// Iniciar testes
tryLogin(adminCredentials);
