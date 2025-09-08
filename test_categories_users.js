const https = require('https');

function testCategoriesAndUsers() {
    console.log('Testando categorias e usuários...');
    
    // Primeiro fazer login para obter token
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
                    
                    // Testar endpoints
                    testQuestions(response.token);
                    testCategories(response.token);
                    testUsers(response.token);
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

function testQuestions(token) {
    console.log('\n=== TESTANDO QUESTÕES ===');
    
    const options = {
        hostname: 'quiz-api-z4ri.onrender.com',
        path: '/admin/questions?limit=5',
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
            console.log('Questions Status:', res.statusCode);
            
            if (res.statusCode === 200) {
                try {
                    const questions = JSON.parse(data);
                    console.log('✓ Total de questões encontradas:', questions.length);
                    
                    questions.slice(0, 3).forEach((q, i) => {
                        console.log(`Questão ${i + 1}:`);
                        console.log('  ID:', q.id);
                        console.log('  Category ID:', q.category_id);
                        console.log('  Category Name:', q.category_name || 'N/A');
                        console.log('  Question:', q.question ? q.question.substring(0, 50) + '...' : 'N/A');
                    });
                } catch (err) {
                    console.log('Erro ao parse questões:', err.message);
                    console.log('Response:', data.substring(0, 200));
                }
            } else {
                console.log('✗ Erro ao buscar questões:', data);
            }
        });
    });
    
    req.on('error', (err) => {
        console.error('Erro na requisição de questões:', err.message);
    });
    
    req.end();
}

function testCategories(token) {
    console.log('\n=== TESTANDO CATEGORIAS ===');
    
    const options = {
        hostname: 'quiz-api-z4ri.onrender.com',
        path: '/categories',
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
            console.log('Categories Status:', res.statusCode);
            
            if (res.statusCode === 200) {
                try {
                    const categories = JSON.parse(data);
                    console.log('✓ Total de categorias encontradas:', categories.length);
                    
                    categories.slice(0, 5).forEach((c, i) => {
                        console.log(`Categoria ${i + 1}: ID=${c.id}, Nome="${c.name}"`);
                    });
                } catch (err) {
                    console.log('Erro ao parse categorias:', err.message);
                    console.log('Response:', data.substring(0, 200));
                }
            } else {
                console.log('✗ Erro ao buscar categorias:', data);
            }
        });
    });
    
    req.on('error', (err) => {
        console.error('Erro na requisição de categorias:', err.message);
    });
    
    req.end();
}

function testUsers(token) {
    console.log('\n=== TESTANDO USUÁRIOS ===');
    
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
            console.log('Users Status:', res.statusCode);
            
            if (res.statusCode === 200) {
                try {
                    const users = JSON.parse(data);
                    console.log('✓ Total de usuários encontrados:', users.length);
                    
                    users.slice(0, 3).forEach((u, i) => {
                        console.log(`Usuário ${i + 1}: ID=${u.id}, Nome="${u.username}", Role="${u.role || u.is_admin ? 'admin' : 'user'}"`);
                    });
                } catch (err) {
                    console.log('Erro ao parse usuários:', err.message);
                    console.log('Response:', data.substring(0, 200));
                }
            } else {
                console.log('✗ Erro ao buscar usuários:', data);
            }
        });
    });
    
    req.on('error', (err) => {
        console.error('Erro na requisição de usuários:', err.message);
    });
    
    req.end();
}

// Iniciar teste
testCategoriesAndUsers();
