require('dotenv').config();
const bcrypt = require('bcrypt');
const db = require('../db');

async function checkUsers() {
  try {
    // Buscar usuários
    const result = await db.query('SELECT id, username, email, name FROM users ORDER BY id LIMIT 10');
    
    console.log('\n📋 USUÁRIOS ENCONTRADOS:');
    console.log('================================');
    result.rows.forEach(user => {
      console.log(`ID: ${user.id} | Username: ${user.username} | Email: ${user.email || 'N/A'} | Nome: ${user.name || 'N/A'}`);
    });
    
    // Verificar senha específica do brunaamor
    const brunaResult = await db.query('SELECT id, username, password FROM users WHERE username = $1', ['brunaamor']);
    
    if (brunaResult.rows.length > 0) {
      const user = brunaResult.rows[0];
      console.log('\n🔍 VERIFICANDO BRUNAAMOR:');
      console.log('================================');
      console.log(`Username: ${user.username}`);
      
      // Testar várias senhas possíveis
      const testPasswords = ['123456', 'brunaamor', 'bruna123', 'admin123'];
      
      for (const testPassword of testPasswords) {
        const isValid = await bcrypt.compare(testPassword, user.password);
        console.log(`Senha "${testPassword}": ${isValid ? '✅ VÁLIDA' : '❌ inválida'}`);
        if (isValid) break;
      }
      
      // Se nenhuma senha funcionou, resetar para 123456
      const isCorrect = await bcrypt.compare('123456', user.password);
      if (!isCorrect) {
        console.log('\n🔧 RESETANDO SENHA PARA 123456...');
        const newHash = await bcrypt.hash('123456', 10);
        await db.query('UPDATE users SET password = $1 WHERE id = $2', [newHash, user.id]);
        console.log('✅ Senha resetada com sucesso!');
      }
    } else {
      console.log('\n❌ Usuário brunaamor não encontrado!');
      
      // Criar usuário brunaamor
      console.log('🔧 Criando usuário brunaamor...');
      const hashedPassword = await bcrypt.hash('123456', 10);
      const createResult = await db.query(
        'INSERT INTO users (username, email, password, name, role) VALUES ($1, $2, $3, $4, $5) RETURNING id, username',
        ['brunaamor', 'brunaamor@test.com', hashedPassword, 'Bruna Amor', 'user']
      );
      console.log('✅ Usuário criado:', createResult.rows[0]);
    }
    
  } catch (err) {
    console.error('❌ Erro:', err);
  }
  
  process.exit(0);
}

checkUsers();
