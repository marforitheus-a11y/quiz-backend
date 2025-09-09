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

async function fixUser() {
  try {
    const client = await pool.connect();
    
    // Hash da nova senha
    const hashedPassword = await bcrypt.hash('brunaamor', 10);
    
    // Atualizar usuário com senha e role
    const result = await client.query(
      'UPDATE users SET password = $1, role = $2 WHERE username = $3 RETURNING id, username, role', 
      [hashedPassword, 'user', 'brunaamor']
    );
    
    if (result.rows.length > 0) {
      const user = result.rows[0];
      console.log('Usuário atualizado com sucesso:');
      console.log(`ID: ${user.id}`);
      console.log(`Username: ${user.username}`);
      console.log(`Role: ${user.role}`);
      console.log('Senha: brunaamor (hash criado)');
    } else {
      console.log('Usuário não encontrado para atualização');
    }
    
    client.release();
    process.exit(0);
  } catch (error) {
    console.error('Erro ao atualizar usuário:', error);
    process.exit(1);
  }
}

fixUser();
