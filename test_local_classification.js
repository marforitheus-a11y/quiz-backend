const { Pool } = require('pg');

// Configuração do banco
const pool = new Pool({
    connectionString: process.env.DATABASE_URL || 'postgresql://postgres:password@localhost:5432/quiz_db',
    ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

async function testClassification() {
    try {
        console.log('Iniciando teste de classificação...');
        
        // Verificar quantas questões sem categoria existem
        const countResult = await pool.query(`
            SELECT COUNT(*) as count 
            FROM questions 
            WHERE category_id = 11
        `);
        
        const semCategoriaCount = parseInt(countResult.rows[0].count);
        console.log(`Encontradas ${semCategoriaCount} questões sem categoria`);
        
        if (semCategoriaCount === 0) {
            console.log('Nenhuma questão para classificar');
            return;
        }
        
        // Pegar uma amostra para testar
        const sampleResult = await pool.query(`
            SELECT id, pergunta, opcoes 
            FROM questions 
            WHERE category_id = 11
            LIMIT 5
        `);
        
        console.log('Amostra de questões:');
        for (const question of sampleResult.rows) {
            const text = `${question.pergunta} ${JSON.stringify(question.opcoes)}`.toLowerCase();
            console.log(`ID: ${question.id}`);
            console.log(`Texto: ${text.substring(0, 100)}...`);
            
            if (text.includes('matemática')) {
                console.log('  -> Classificaria como Matemática');
            } else if (text.includes('português')) {
                console.log('  -> Classificaria como Português');
            } else if (text.includes('trânsito')) {
                console.log('  -> Classificaria como Agente de trânsito');
            } else {
                console.log('  -> Permaneceria sem categoria');
            }
            console.log('---');
        }
        
    } catch (error) {
        console.error('Erro no teste:', error);
    } finally {
        await pool.end();
    }
}

testClassification();
