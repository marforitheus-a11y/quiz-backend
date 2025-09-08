const { Pool } = require('pg');

const db = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

async function checkTables() {
    try {
        console.log('Verificando estrutura da tabela users...');
        const usersStructure = await db.query(`
            SELECT column_name, data_type 
            FROM information_schema.columns 
            WHERE table_name = 'users'
            ORDER BY ordinal_position
        `);
        console.log('Estrutura da tabela users:');
        usersStructure.rows.forEach(row => {
            console.log(`- ${row.column_name}: ${row.data_type}`);
        });
        
        console.log('\nVerificando estrutura da tabela questions...');
        const questionsStructure = await db.query(`
            SELECT column_name, data_type 
            FROM information_schema.columns 
            WHERE table_name = 'questions'
            ORDER BY ordinal_position
        `);
        console.log('Estrutura da tabela questions:');
        questionsStructure.rows.forEach(row => {
            console.log(`- ${row.column_name}: ${row.data_type}`);
        });
        
        console.log('\nVerificando estrutura da tabela categories...');
        const categoriesStructure = await db.query(`
            SELECT column_name, data_type 
            FROM information_schema.columns 
            WHERE table_name = 'categories'
            ORDER BY ordinal_position
        `);
        console.log('Estrutura da tabela categories:');
        categoriesStructure.rows.forEach(row => {
            console.log(`- ${row.column_name}: ${row.data_type}`);
        });
        
    } catch (err) {
        console.error('Erro:', err.message);
    } finally {
        await db.end();
        process.exit(0);
    }
}

checkTables();
