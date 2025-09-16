// =================================================================
// DATABASE CONFIGURATION - Configuração completa do PostgreSQL
// =================================================================

const { Pool } = require('pg');

// Carregar variáveis de ambiente
if (process.env.NODE_ENV !== 'production') {
    require('dotenv').config();
}

// =================================================================
// CONFIGURAÇÃO DA CONEXÃO
// =================================================================

// Detectar se SSL é necessário
const isProduction = process.env.NODE_ENV === 'production';
const forceSSL = process.env.DB_FORCE_SSL === 'true';
const shouldUseSSL = isProduction || forceSSL;

// Configuração do pool de conexões
const poolConfig = {
    connectionString: process.env.DATABASE_URL,
    ssl: shouldUseSSL ? {
        rejectUnauthorized: false,
        require: true
    } : false,
    max: 20,          // máximo de conexões no pool
    idleTimeoutMillis: 30000,
    connectionTimeoutMillis: 2000,
    maxUses: 7500,    // renovar conexão após N usos
    allowExitOnIdle: false
};

// Fallback para configuração manual se DATABASE_URL não estiver definida
if (!process.env.DATABASE_URL) {
    poolConfig.user = process.env.POSTGRES_USER;
    poolConfig.host = process.env.POSTGRES_HOST || 'localhost';
    poolConfig.database = process.env.POSTGRES_DB;
    poolConfig.password = process.env.POSTGRES_PASSWORD;
    poolConfig.port = process.env.POSTGRES_PORT || 5432;
}

// Criar pool de conexões
const pool = new Pool(poolConfig);

// =================================================================
// LOGS E MONITORAMENTO
// =================================================================

pool.on('connect', (client) => {
    console.log('✅ Nova conexão estabelecida com o banco');
});

pool.on('error', (err, client) => {
    console.error('❌ Erro inesperado no cliente do banco:', err);
    process.exit(-1);
});

// =================================================================
// TESTE DE CONEXÃO
// =================================================================
async function testConnection() {
    try {
        console.log('🔍 Testando conexão com o banco...');
        
        const client = await pool.connect();
        
        // Teste básico
        const result = await client.query('SELECT NOW() as current_time, version() as pg_version');
        console.log('✅ Banco conectado com sucesso!');
        console.log(`   Hora do servidor: ${result.rows[0].current_time}`);
        console.log(`   Versão PostgreSQL: ${result.rows[0].pg_version.split(' ')[0]}`);
        
        // Verificar se tabelas principais existem
        const tablesQuery = `
            SELECT table_name 
            FROM information_schema.tables 
            WHERE table_schema = 'public' 
            AND table_name IN ('users', 'questions', 'quiz_history')
            ORDER BY table_name
        `;
        
        const tablesResult = await client.query(tablesQuery);
        const existingTables = tablesResult.rows.map(row => row.table_name);
        
        console.log('📋 Tabelas encontradas:', existingTables);
        
        if (existingTables.length === 0) {
            console.log('⚠️  Nenhuma tabela principal encontrada. O banco pode precisar de inicialização.');
        }
        
        client.release();
        return true;
        
    } catch (error) {
        console.error('❌ Erro ao conectar com o banco:');
        console.error('   Mensagem:', error.message);
        console.error('   Código:', error.code);
        
        if (error.code === 'ECONNREFUSED') {
            console.error('   O servidor PostgreSQL pode estar desligado ou inacessível.');
        } else if (error.code === 'ENOTFOUND') {
            console.error('   Host do banco não encontrado. Verifique a configuração.');
        } else if (error.code === '28P01') {
            console.error('   Credenciais inválidas. Verifique usuário e senha.');
        }
        
        return false;
    }
}

// =================================================================
// WRAPPER DE QUERY COM LOG
// =================================================================
async function query(text, params = []) {
    const start = Date.now();
    
    try {
        const result = await pool.query(text, params);
        const duration = Date.now() - start;
        
        // Log apenas para queries demoradas ou em desenvolvimento
        if (duration > 1000 || process.env.NODE_ENV === 'development') {
            console.log(`📊 Query executada em ${duration}ms:`, {
                query: text.substring(0, 100) + (text.length > 100 ? '...' : ''),
                rows: result.rowCount,
                params: params.length
            });
        }
        
        return result;
        
    } catch (error) {
        const duration = Date.now() - start;
        console.error(`❌ Query falhou após ${duration}ms:`, {
            error: error.message,
            query: text.substring(0, 100) + (text.length > 100 ? '...' : ''),
            params: params.length
        });
        throw error;
    }
}

// =================================================================
// TRANSAÇÕES
// =================================================================
async function transaction(callback) {
    const client = await pool.connect();
    
    try {
        await client.query('BEGIN');
        const result = await callback(client);
        await client.query('COMMIT');
        return result;
    } catch (error) {
        await client.query('ROLLBACK');
        throw error;
    } finally {
        client.release();
    }
}

// =================================================================
// GRACEFUL SHUTDOWN
// =================================================================
async function closePool() {
    try {
        await pool.end();
        console.log('✅ Pool de conexões fechado graciosamente');
    } catch (error) {
        console.error('❌ Erro ao fechar pool:', error);
    }
}

// Eventos de shutdown
process.on('SIGINT', async () => {
    console.log('\n🛑 Recebido SIGINT, fechando conexões...');
    await closePool();
    process.exit(0);
});

process.on('SIGTERM', async () => {
    console.log('\n🛑 Recebido SIGTERM, fechando conexões...');
    await closePool();
    process.exit(0);
});

// =================================================================
// INICIALIZAÇÃO
// =================================================================
async function initialize() {
    const isConnected = await testConnection();
    
    if (!isConnected) {
        console.error('❌ Falha ao conectar com o banco. Verifique as configurações.');
        process.exit(1);
    }
    
    return pool;
}

// =================================================================
// EXPORTS
// =================================================================
module.exports = {
    query,
    transaction,
    pool,
    initialize,
    closePool,
    testConnection
};
