// arquivo: db.js
const { Pool } = require('pg');

// Configura a conexão com o banco de dados PostgreSQL que está rodando no Docker
const pool = new Pool({
    user: 'postgres',
    host: 'localhost',
    database: 'postgres', // O banco de dados padrão do PostgreSQL
    password: 'mysecretpassword',
    port: 5432,
});

// Exporta uma função que podemos usar para fazer queries
module.exports = {
    query: (text, params) => pool.query(text, params),
};