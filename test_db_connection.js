// Pequeno script para testar a conexão com o banco de dados de forma independente.
// Execute com: node test_db_connection.js

// Carrega as variáveis do .env
require('dotenv').config(); 

const { Pool } = require('pg');

const connectionString = process.env.DATABASE_URL;

if (!connectionString) {
    console.error('ERRO: A variável de ambiente DATABASE_URL não está definida no seu arquivo .env.');
    process.exit(1);
}

console.log('Tentando conectar ao banco de dados...');
console.log(`(Usando a connection string do seu .env)`);

// Força o uso de 127.0.0.1 e desabilita SSL para teste local
const pool = new Pool({
    connectionString: connectionString.replace('localhost', '127.0.0.1'), 
    ssl: false,
    connectionTimeoutMillis: 5000 // Timeout de 5 segundos
});

pool.connect((err, client, release) => {
    if (err) {
        console.error('--------------------------------------------------');
        console.error('FALHA NA CONEXÃO COM O BANCO DE DADOS.');
        console.error('--------------------------------------------------');
        console.error('Erro detalhado:', err.message);
        console.error('\nPossíveis causas:');
        console.error('1. O servidor PostgreSQL não está rodando.');
        console.error('2. A DATABASE_URL no arquivo .env está incorreta (usuário, senha, nome do banco).');
        console.error('3. O PostgreSQL não está configurado para aceitar conexões TCP/IP (verificar postgresql.conf).');
        console.error('4. Um firewall está bloqueando a porta 5432.');
        pool.end();
        process.exit(1);
    } else {
        console.log('--------------------------------------------------');
        console.log('✅ CONEXÃO COM O BANCO DE DADOS BEM-SUCEDIDA!');
        console.log('--------------------------------------------------');
        client.release();
        pool.end();
        process.exit(0);
    }
});
