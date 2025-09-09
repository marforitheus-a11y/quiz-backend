require('dotenv').config();
const db = require('./db');
const bcrypt = require('bcrypt');

async function checkUser() {
    try {
        const result = await db.query('SELECT id, username, role, password FROM users WHERE username = $1', ['brunaamor']);
        
        if (result.rows.length === 0) {
            console.log('Usuario brunaamor não encontrado. Criando...');
            const hashedPassword = await bcrypt.hash('brunaamor', 10);
            
            const newUser = await db.query(
                'INSERT INTO users (username, password, role) VALUES ($1, $2, $3) RETURNING id, username, role',
                ['brunaamor', hashedPassword, 'user']
            );
            
            console.log('Usuário criado:', newUser.rows[0]);
            console.log('Credenciais: username=brunaamor, password=brunaamor');
        } else {
            console.log('Usuario brunaamor encontrado:', { id: result.rows[0].id, username: result.rows[0].username, role: result.rows[0].role });
            
            // Testar senha
            const passwordMatch = await bcrypt.compare('brunaamor', result.rows[0].password);
            console.log('Senha "brunaamor" confere:', passwordMatch);
            
            if (!passwordMatch) {
                console.log('Senha não confere. Atualizando senha...');
                const hashedPassword = await bcrypt.hash('brunaamor', 10);
                await db.query('UPDATE users SET password = $1 WHERE username = $2', [hashedPassword, 'brunaamor']);
                console.log('Senha atualizada para "brunaamor"');
            }
        }
        
        process.exit(0);
    } catch (err) {
        console.error('Erro:', err);
        process.exit(1);
    }
}

checkUser();
