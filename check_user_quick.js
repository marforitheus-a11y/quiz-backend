const { Pool } = require('pg');
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

async function checkUser() {
  try {
    const client = await pool.connect();
    
    const result = await client.query('SELECT id, name, username, role FROM users WHERE username = $1', ['brunaamor']);
    
    if (result.rows.length > 0) {
      const user = result.rows[0];
      console.log('Usuário encontrado:');
      console.log(`ID: ${user.id}`);
      console.log(`Nome: ${user.name}`);
      console.log(`Username: ${user.username}`);
      console.log(`Role: ${user.role}`);
    } else {
      console.log('Usuário brunaamor não encontrado no banco');
    }
    
    client.release();
    process.exit(0);
  } catch (error) {
    console.error('Erro ao verificar usuário:', error);
    process.exit(1);
  }
}

checkUser();
