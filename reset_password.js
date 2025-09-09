require('dotenv').config();
const db = require('./db');
const bcrypt = require('bcrypt');

async function resetPassword() {
    try {
        console.log('Resetando senha do usuário brunaamor...');
        
        const hashedPassword = await bcrypt.hash('brunaamor', 10);
        const result = await db.query(
            'UPDATE users SET password = $1 WHERE username = $2 RETURNING id, username, role',
            [hashedPassword, 'brunaamor']
        );
        
        if (result.rows.length > 0) {
            console.log('Senha atualizada com sucesso para o usuário:', result.rows[0]);
            console.log('Credenciais: username=brunaamor, password=brunaamor');
        } else {
            console.log('Usuário brunaamor não encontrado');
        }
        
        process.exit(0);
    } catch (err) {
        console.error('Erro:', err);
        process.exit(1);
    }
}

resetPassword();
