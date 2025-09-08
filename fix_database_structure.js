const { Pool } = require('pg');

const db = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

async function fixDatabaseStructure() {
    try {
        console.log('Corrigindo estrutura do banco de dados...');
        
        // Adicionar created_at na tabela users se não existir
        try {
            await db.query(`
                ALTER TABLE users 
                ADD COLUMN IF NOT EXISTS created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            `);
            console.log('✓ Coluna created_at adicionada na tabela users');
        } catch (err) {
            console.log('- Coluna created_at já existe na tabela users ou erro:', err.message);
        }
        
        // Adicionar created_at na tabela questions se não existir
        try {
            await db.query(`
                ALTER TABLE questions 
                ADD COLUMN IF NOT EXISTS created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            `);
            console.log('✓ Coluna created_at adicionada na tabela questions');
        } catch (err) {
            console.log('- Coluna created_at já existe na tabela questions ou erro:', err.message);
        }
        
        // Adicionar created_at na tabela categories se não existir
        try {
            await db.query(`
                ALTER TABLE categories 
                ADD COLUMN IF NOT EXISTS created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            `);
            console.log('✓ Coluna created_at adicionada na tabela categories');
        } catch (err) {
            console.log('- Coluna created_at já existe na tabela categories ou erro:', err.message);
        }
        
        // Adicionar difficulty na tabela questions se não existir
        try {
            await db.query(`
                ALTER TABLE questions 
                ADD COLUMN IF NOT EXISTS difficulty TEXT DEFAULT 'medium'
            `);
            console.log('✓ Coluna difficulty adicionada na tabela questions');
        } catch (err) {
            console.log('- Coluna difficulty já existe na tabela questions ou erro:', err.message);
        }
        
        // Adicionar category_id na tabela questions se não existir
        try {
            await db.query(`
                ALTER TABLE questions 
                ADD COLUMN IF NOT EXISTS category_id INTEGER
            `);
            console.log('✓ Coluna category_id adicionada na tabela questions');
        } catch (err) {
            console.log('- Coluna category_id já existe na tabela questions ou erro:', err.message);
        }
        
        // Criar tabela reports se não existir
        try {
            await db.query(`
                CREATE TABLE IF NOT EXISTS reports (
                    id SERIAL PRIMARY KEY,
                    question_id INTEGER REFERENCES questions(id) ON DELETE CASCADE,
                    user_id INTEGER,
                    reason TEXT,
                    description TEXT,
                    status TEXT DEFAULT 'pending',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            `);
            console.log('✓ Tabela reports criada/verificada');
        } catch (err) {
            console.log('- Erro ao criar tabela reports:', err.message);
        }
        
        // Criar tabela quiz_sessions se não existir
        try {
            await db.query(`
                CREATE TABLE IF NOT EXISTS quiz_sessions (
                    id SERIAL PRIMARY KEY,
                    user_id INTEGER REFERENCES users(id),
                    score DECIMAL(5,2),
                    questions_answered INTEGER DEFAULT 0,
                    correct_answers INTEGER DEFAULT 0,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            `);
            console.log('✓ Tabela quiz_sessions criada/verificada');
        } catch (err) {
            console.log('- Erro ao criar tabela quiz_sessions:', err.message);
        }
        
        // Criar tabela themes se não existir
        try {
            await db.query(`
                CREATE TABLE IF NOT EXISTS themes (
                    id SERIAL PRIMARY KEY,
                    name TEXT NOT NULL,
                    description TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            `);
            console.log('✓ Tabela themes criada/verificada');
        } catch (err) {
            console.log('- Erro ao criar tabela themes:', err.message);
        }
        
        console.log('\n✓ Estrutura do banco de dados corrigida com sucesso!');
        
    } catch (err) {
        console.error('Erro ao corrigir estrutura do banco:', err.message);
    } finally {
        await db.end();
        process.exit(0);
    }
}

fixDatabaseStructure();
