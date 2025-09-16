const https = require('https');

function testUserDeletion() {
    console.log('Testando correção do endpoint DELETE de usuários...');
    
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
                    
                    // Primeiro listar usuários
                    listUsers(response.token);
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

function listUsers(token) {
    console.log('\n=== LISTANDO USUÁRIOS ===');
    
    const options = {
        hostname: 'quiz-api-z4ri.onrender.com',
        path: '/admin/users',
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
            console.log('List Users Status:', res.statusCode);
            
            if (res.statusCode === 200) {
                try {
                    const users = JSON.parse(data);
                    console.log(`✓ Total de usuários: ${users.length}`);
                    
                    // Mostrar alguns usuários (não admins)
                    const regularUsers = users.filter(u => u.role !== 'admin');
                    console.log(`✓ Usuários não-admin: ${regularUsers.length}`);
                    
                    regularUsers.slice(0, 3).forEach((u, i) => {
                        console.log(`  ${i + 1}. ID: ${u.id}, Username: ${u.username}, Role: ${u.role || 'user'}`);
                    });
                    
                    // Testar tentativa de exclusão de um usuário inexistente
                    testDeleteNonExistentUser(token);
                    
                } catch (err) {
                    console.log('Erro ao parse usuários:', err.message);
                    console.log('Response:', data.substring(0, 500));
                }
            } else {
                console.log('✗ Erro ao listar usuários:', data);
            }
        });
    });
    
    req.on('error', (err) => {
        console.error('Erro na requisição de usuários:', err.message);
    });
    
    req.end();
}

function testDeleteNonExistentUser(token) {
    console.log('\n=== TESTANDO DELETE DE USUÁRIO INEXISTENTE ===');
    
    // Tentar excluir usuário com ID muito alto (que provavelmente não existe)
    const fakeUserId = 99999;
    
    const options = {
        hostname: 'quiz-api-z4ri.onrender.com',
        path: `/admin/users/${fakeUserId}`,
        method: 'DELETE',
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
            console.log(`Delete User ${fakeUserId} Status:`, res.statusCode);
            
            if (res.statusCode === 404) {
                try {
                    const response = JSON.parse(data);
                    console.log('✓ Endpoint DELETE funcionando! Resposta JSON válida:');
                    console.log('  Mensagem:', response.message);
                    console.log('✓ PROBLEMA RESOLVIDO: Não há mais erro "Unexpected token"');
                } catch (err) {
                    console.log('✗ Ainda há problema com JSON:', err.message);
                    console.log('Response raw:', data);
                }
            } else if (res.statusCode === 200) {
                console.log('⚠️ Usuário foi excluído (não esperado para ID alto)');
                console.log('Response:', data);
            } else {
                console.log('Status inesperado:', res.statusCode);
                console.log('Response:', data);
            }
        });
    });
    
    req.on('error', (err) => {
        console.error('Erro na requisição de delete:', err.message);
    });
    
    req.end();
}

// Iniciar teste
testUserDeletion();
