require('dotenv').config();
const bcrypt = require('bcrypt');
const db = require('./db');

async function createTestUser() {
    try {
        // Deletar usuário existente
        await db.query('DELETE FROM users WHERE username = $1', ['test_user']);
        
        // Criar novo usuário
        const hashed = await bcrypt.hash('123456', 10);
        const result = await db.query(
            'INSERT INTO users (username, password, role) VALUES ($1, $2, $3) RETURNING id, username, role',
            ['test_user', hashed, 'user']
        );
        
        console.log('Usuario criado:', result.rows[0]);
        console.log('Credenciais: username=test_user, password=123456');
        
        process.exit(0);
    } catch (err) {
        console.error('Erro:', err);
        process.exit(1);
    }
}

createTestUser();
