const { Pool } = require('pg');
const bcrypt = require('bcrypt');
require('dotenv').config();

const isProduction = process.env.NODE_ENV === 'production';

// Build connection string: prefer DATABASE_URL, fallback to individual DB_* vars
let connectionString = process.env.DATABASE_URL;
if (!connectionString) {
    const { DB_USER, DB_PASSWORD, DB_HOST, DB_PORT, DB_DATABASE } = process.env;
    if (DB_USER && DB_PASSWORD && DB_HOST && DB_PORT && DB_DATABASE) {
        connectionString = `postgresql://${DB_USER}:${DB_PASSWORD}@${DB_HOST}:${DB_PORT}/${DB_DATABASE}`;
    }
}

if (connectionString && typeof connectionString === 'string') {
    connectionString = connectionString.trim();
    connectionString = connectionString.replace(/\/(\w+)\s+$/, '/$1');
}

// Determine SSL option
let sslOption = false;
if (process.env.DB_FORCE_SSL === 'true') {
    sslOption = { rejectUnauthorized: false };
} else if (connectionString && connectionString.includes('render.com')) {
    sslOption = { rejectUnauthorized: false };
} else if (isProduction && connectionString) {
    sslOption = { rejectUnauthorized: false };
}

const pool = new Pool({
    connectionString: connectionString,
    ssl: sslOption,
    idleTimeoutMillis: 30000,
    connectionTimeoutMillis: 10000
});

async function testPassword() {
  try {
    const client = await pool.connect();
    
    // Buscar o usuário
    const result = await client.query('SELECT id, username, password, role FROM users WHERE username = $1', ['brunaamor']);
    
    if (result.rows.length === 0) {
      console.log('❌ Usuário brunaamor não encontrado');
      client.release();
      return;
    }
    
    const user = result.rows[0];
    console.log('✅ Usuário encontrado:');
    console.log(`ID: ${user.id}`);
    console.log(`Username: ${user.username}`);
    console.log(`Role: ${user.role}`);
    console.log(`Password Hash: ${user.password.substring(0, 20)}...`);
    
    // Testar a senha
    const passwordToTest = 'brunaamor';
    console.log(`\n🔍 Testando senha: "${passwordToTest}"`);
    
    const isValid = await bcrypt.compare(passwordToTest, user.password);
    
    if (isValid) {
      console.log('✅ SENHA VÁLIDA! A comparação bcrypt funcionou.');
    } else {
      console.log('❌ SENHA INVÁLIDA! A comparação bcrypt falhou.');
      
      // Vamos criar um novo hash e testar
      console.log('\n🔄 Criando novo hash...');
      const newHash = await bcrypt.hash(passwordToTest, 10);
      console.log(`Novo hash: ${newHash.substring(0, 20)}...`);
      
      const testNewHash = await bcrypt.compare(passwordToTest, newHash);
      console.log(`Teste com novo hash: ${testNewHash ? '✅ VÁLIDO' : '❌ INVÁLIDO'}`);
      
      // Atualizar com o novo hash
      await client.query('UPDATE users SET password = $1 WHERE username = $2', [newHash, 'brunaamor']);
      console.log('🔄 Password atualizado no banco de dados');
    }
    
    client.release();
    process.exit(0);
  } catch (error) {
    console.error('❌ Erro:', error);
    process.exit(1);
  }
}

testPassword();
