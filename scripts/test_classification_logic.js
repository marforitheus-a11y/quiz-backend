const { Pool } = require('pg');

// Database connection
const pool = new Pool({
    connectionString: process.env.DATABASE_URL || 'postgresql://quiz_db_l15y_user:gf5KYEDqjQQkFFEW3WFm7Yt0dADJcDuM@dpg-csslqai3esus739hc9tg-a.ohio-postgres.render.com/quiz_db_l15y',
    ssl: {
        rejectUnauthorized: false
    }
});

// Keywords for each category
const categoryKeywords = {
    3: ['trânsito', 'transit', 'agente', 'sinalização', 'multa', 'veículo', 'condutor', 'habilitação', 'código', 'cnh'],
    4: ['educação', 'ensino', 'professor', 'pedagógico', 'aprendizagem', 'didática', 'currículo', 'escola', 'aluno', 'avaliação'],
    5: ['matemática', 'número', 'cálculo', 'equação', 'função', 'geometria', 'álgebra', 'aritmética', 'estatística', 'trigonometria'],
    6: ['português', 'gramática', 'texto', 'literatura', 'redação', 'ortografia', 'sintaxe', 'semântica', 'fonética', 'concordância'],
    7: ['gcm', 'diadema', 'guarda civil municipal', 'município', 'patrulhamento', 'ronda', 'segurança pública', 'ordenamento', 'fiscalização'],
    8: ['gcm', 'hortolândia', 'guarda civil municipal', 'município', 'patrulhamento', 'ronda', 'segurança pública', 'ordenamento', 'fiscalização']
};

function classifyQuestion(questionText) {
    const text = questionText.toLowerCase();
    let bestMatch = { categoryId: 11, score: 0 }; // Default to "Sem Categoria"
    
    for (const [categoryId, keywords] of Object.entries(categoryKeywords)) {
        let score = 0;
        
        for (const keyword of keywords) {
            if (text.includes(keyword.toLowerCase())) {
                score++;
            }
        }
        
        if (score > bestMatch.score) {
            bestMatch = { categoryId: parseInt(categoryId), score };
        }
    }
    
    return bestMatch.categoryId;
}

async function testClassification() {
    try {
        console.log('Testing classification logic...\n');
        
        // Test with some sample questions
        const testQuestions = [
            'Qual é a velocidade máxima permitida em vias urbanas?',
            'O professor deve considerar a didática adequada para ensinar',
            'Calcule a raiz quadrada de 144',
            'A concordância verbal é um aspecto importante da gramática',
            'A Guarda Civil Municipal de Diadema tem como função',
            'O patrulhamento em Hortolândia é realizado pela GCM',
            'Esta é uma questão sem categoria específica'
        ];
        
        testQuestions.forEach((question, index) => {
            const categoryId = classifyQuestion(question);
            console.log(`Questão ${index + 1}: "${question}"`);
            console.log(`Categoria classificada: ${categoryId}\n`);
        });
        
        // Test with actual database questions
        console.log('Testing with sample database questions...\n');
        
        const result = await pool.query(`
            SELECT id, question, category_id 
            FROM questions 
            WHERE category_id = 11 
            LIMIT 5
        `);
        
        for (const question of result.rows) {
            const newCategoryId = classifyQuestion(question.question);
            console.log(`ID: ${question.id}`);
            console.log(`Questão: "${question.question.substring(0, 100)}..."`);
            console.log(`Categoria atual: ${question.category_id}`);
            console.log(`Nova categoria sugerida: ${newCategoryId}`);
            console.log('---');
        }
        
    } catch (error) {
        console.error('Error testing classification:', error);
    } finally {
        await pool.end();
    }
}

testClassification();
