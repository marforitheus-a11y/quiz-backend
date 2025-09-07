// Script para inserir reportes de teste
const { Pool } = require('pg');
require('dotenv').config();

const db = new Pool({
    connectionString: process.env.DATABASE_URL
});

async function insertTestReports() {
    try {
        // Primeiro, vamos verificar se existem questões
        const questions = await db.query('SELECT id FROM questions LIMIT 5');
        
        if (questions.rows.length === 0) {
            console.log('Nenhuma questão encontrada. Criando uma questão de teste...');
            
            // Criar uma questão de teste
            const insertQuestion = await db.query(`
                INSERT INTO questions (question, options, difficulty, correct_answer, category_id, theme_id)
                VALUES ($1, $2, $3, $4, $5, $6)
                RETURNING id
            `, [
                'Questão de teste para reportes',
                JSON.stringify(['Opção A', 'Opção B', 'Opção C', 'Opção D']),
                'easy',
                0,
                1,
                1
            ]);
            
            console.log('Questão de teste criada com ID:', insertQuestion.rows[0].id);
        }
        
        // Buscar questões novamente
        const availableQuestions = await db.query('SELECT id FROM questions LIMIT 3');
        
        // Criar alguns reportes de teste
        const testReports = [
            {
                question_id: availableQuestions.rows[0].id,
                reason: 'Erro de gramática',
                description: 'A questão contém erros de gramática que podem confundir os candidatos.',
                user_id: null
            },
            {
                question_id: availableQuestions.rows[0].id,
                reason: 'Resposta incorreta',
                description: 'A resposta marcada como correta parece estar errada.',
                user_id: null
            }
        ];
        
        if (availableQuestions.rows.length > 1) {
            testReports.push({
                question_id: availableQuestions.rows[1].id,
                reason: 'Enunciado confuso',
                description: 'O enunciado da questão não está claro.',
                user_id: null
            });
        }
        
        for (const report of testReports) {
            const result = await db.query(`
                INSERT INTO reports (question_id, reason, description, user_id, status)
                VALUES ($1, $2, $3, $4, 'pending')
                RETURNING id
            `, [report.question_id, report.reason, report.description, report.user_id]);
            
            console.log('Reporte inserido com ID:', result.rows[0].id);
        }
        
        console.log('Reportes de teste inseridos com sucesso!');
        
        // Verificar os reportes inseridos
        const allReports = await db.query(`
            SELECT 
                r.id, 
                r.question_id, 
                r.status, 
                r.reason, 
                r.description, 
                r.created_at 
            FROM reports r
            ORDER BY r.created_at DESC
        `);
        
        console.log('Total de reportes na base:', allReports.rows.length);
        console.log('Reportes:', allReports.rows);
        
    } catch (error) {
        console.error('Erro ao inserir reportes de teste:', error);
    } finally {
        await db.end();
    }
}

insertTestReports();
