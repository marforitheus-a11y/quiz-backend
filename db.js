// arquivo: db.js (MODIFICADO)
const { Pool } = require('pg');
// Carrega as variáveis de ambiente do arquivo .env APENAS em desenvolvimento
if (process.env.NODE_ENV !== 'production') {
    require('dotenv').config();
}

const isProduction = process.env.NODE_ENV === 'production';

let connectionString = process.env.DATABASE_URL;
if (!connectionString) {
    const { DB_USER, DB_PASSWORD, DB_HOST, DB_PORT, DB_DATABASE } = process.env;
    if (!DB_USER || !DB_PASSWORD || !DB_HOST || !DB_PORT || !DB_DATABASE) {
        console.error('Database configuration missing. Set DATABASE_URL or DB_* environment variables.');
        process.exit(1);
    }
    connectionString = `postgresql://${DB_USER}:${DB_PASSWORD}@${DB_HOST}:${DB_PORT}/${DB_DATABASE}`;
}

const pool = new Pool({
    connectionString: connectionString,
    ssl: isProduction ? { rejectUnauthorized: false } : false,
    idleTimeoutMillis: 30000,
    connectionTimeoutMillis: 2000
});

pool.on('error', (err) => {
    console.error('Unexpected error on idle client', err);
});

module.exports = {
    query: (text, params) => pool.query(text, params),
};