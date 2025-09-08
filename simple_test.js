const { Pool } = require('pg');

// Verificar variáveis de ambiente
console.log('DATABASE_URL:', process.env.DATABASE_URL ? 'SET' : 'NOT SET');
console.log('NODE_ENV:', process.env.NODE_ENV);

const db = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

async function simpleTest() {
    try {
        console.log('\nTestando conexão básica...');
        
        // Test básico
        const basicTest = await db.query('SELECT 1 as test');
        console.log('✓ Conexão funcionando:', basicTest.rows[0]);
        
        // Verificar tabelas existentes
        const tables = await db.query(`
            SELECT table_name 
            FROM information_schema.tables 
            WHERE table_schema = 'public'
        `);
        console.log('\nTabelas encontradas:');
        tables.rows.forEach(row => console.log('-', row.table_name));
        
        // Verificar estrutura da tabela users
        const usersStructure = await db.query(`
            SELECT column_name, data_type 
            FROM information_schema.columns 
            WHERE table_name = 'users'
            ORDER BY ordinal_position
        `);
        console.log('\nEstrutura da tabela users:');
        usersStructure.rows.forEach(row => {
            console.log(`- ${row.column_name}: ${row.data_type}`);
        });
        
        // Teste simples de count
        const userCount = await db.query('SELECT COUNT(*) as count FROM users');
        console.log('\nTotal de usuários:', userCount.rows[0].count);
        
    } catch (err) {
        console.error('Erro:', err.message);
    } finally {
        await db.end();
        process.exit(0);
    }
}

simpleTest();
