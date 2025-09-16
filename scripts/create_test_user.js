// Script para criar usuário de teste brunaamor
require('dotenv').config();
const bcrypt = require('bcrypt');
const db = require('../db');

async function main() {
  const username = 'brunaamor';
  const email = 'brunaamor@teste.com';
  const password = '123456';
  const name = 'Bruna Amor';
  
  try {
    // Verifica se usuário já existe
    const existing = await db.query('SELECT id FROM users WHERE username = $1 OR email = $2', [username, email]);
    
    if (existing.rows.length > 0) {
      console.log('✅ Usuário já existe:', existing.rows[0]);
      console.log('📋 Credenciais:');
      console.log('   Username:', username);
      console.log('   Password:', password);
      console.log('   Email:', email);
      process.exit(0);
    }
    
    // Cria hash da senha
    const hashed = await bcrypt.hash(password, 10);
    
    // Insere novo usuário
    const result = await db.query(
      'INSERT INTO users (username, email, password, name, role) VALUES ($1, $2, $3, $4, $5) RETURNING id, username, email, name, role',
      [username, email, hashed, name, 'user']
    );
    
    console.log('✅ Usuário criado com sucesso:', result.rows[0]);
    console.log('📋 Credenciais:');
    console.log('   Username:', username);
    console.log('   Password:', password);
    console.log('   Email:', email);
    
    process.exit(0);
  } catch (err) {
    console.error('❌ Erro ao criar usuário:', err);
    process.exit(1);
  }
}

main();
