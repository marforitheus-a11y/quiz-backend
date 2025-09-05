// arquivo: db.js (robusto, detecta SSL para provedores gerenciados como Render)
const { Pool } = require('pg');
// Carrega as variáveis de ambiente do arquivo .env APENAS em desenvolvimento
if (process.env.NODE_ENV !== 'production') {
    require('dotenv').config();
}

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
    // defensive: remove accidental trailing spaces after DB name
    connectionString = connectionString.replace(/\/(\w+)\s+$/, '/$1');
}

// Determine SSL option: explicit env flag, or managed host heuristics
let sslOption = false;
if (process.env.DB_FORCE_SSL === 'true') {
    sslOption = { rejectUnauthorized: false };
} else if (connectionString && connectionString.includes('render.com')) {
    sslOption = { rejectUnauthorized: false };
} else if (isProduction && connectionString) {
    // conservative default in production: enable SSL (rejectUnauthorized false for typical providers)
    sslOption = { rejectUnauthorized: false };
}

const pool = new Pool({
    connectionString: connectionString,
    ssl: sslOption,
    idleTimeoutMillis: 30000,
    connectionTimeoutMillis: 10000
});

pool.on('error', (err) => {
    console.error('Unexpected error on idle PostgreSQL client', err && err.message ? err.message : err);
});

module.exports = {
    query: async (text, params) => {
        try {
            return await pool.query(text, params);
        } catch (err) {
            console.error('DB query error', err && err.message ? err.message : err);
            throw err;
        }
    },
    testConnection: async () => {
        try {
            const r = await pool.query('SELECT 1');
            return r && r.rowCount === 1;
        } catch (err) {
            console.error('DB healthcheck failed', err && err.message ? err.message : err);
            return false;
        }
    }
};