require('dotenv').config();
const bcrypt = require('bcrypt');
const db = require('../db');

async function test() {
  try {
    const result = await db.query('SELECT id, username, password FROM users WHERE username = $1', ['brunaamor']);
    if (result.rows.length > 0) {
      const user = result.rows[0];
      console.log('✅ Usuário encontrado:', user.username);
      const isValid = await bcrypt.compare('123456', user.password);
      console.log('✅ Senha válida:', isValid);
      
      if (!isValid) {
        console.log('❌ Hash atual:', user.password.substring(0, 20) + '...');
        // Atualizar com nova senha
        const newHash = await bcrypt.hash('123456', 10);
        await db.query('UPDATE users SET password = $1 WHERE id = $2', [newHash, user.id]);
        console.log('✅ Senha atualizada com sucesso!');
      }
    } else {
      console.log('❌ Usuário não encontrado');
    }
  } catch (err) {
    console.error('❌ Erro:', err);
  }
  process.exit(0);
}

test();
