const { Pool } = require("pg");
require("dotenv").config();
const pool = new Pool({ connectionString: process.env.DATABASE_URL });

async function checkTables() {
    try {
        // Verificar tabelas existentes
        const tables = await pool.query(`
            SELECT table_name 
            FROM information_schema.tables 
            WHERE table_schema = 'public' 
            ORDER BY table_name
        `);
        
        console.log(" Tabelas existentes:");
        tables.rows.forEach(row => console.log(" -", row.table_name));
        
        // Verificar se quiz_results existe
        const quizResults = await pool.query(`
            SELECT column_name, data_type 
            FROM information_schema.columns 
            WHERE table_name = 'quiz_results'
        `);
        
        if (quizResults.rows.length === 0) {
            console.log("  Tabela quiz_results não existe - criando...");
            await pool.query(`
                CREATE TABLE IF NOT EXISTS quiz_results (
                    id SERIAL PRIMARY KEY,
                    user_id INTEGER REFERENCES users(id),
                    score INTEGER NOT NULL,
                    total_questions INTEGER NOT NULL,
                    completed_at TIMESTAMP DEFAULT NOW()
                )
            `);
            console.log(" Tabela quiz_results criada");
        } else {
            console.log(" Tabela quiz_results existe");
        }
        
        await pool.end();
    } catch (err) {
        console.error(" Erro:", err.message);
        process.exit(1);
    }
}

checkTables();
