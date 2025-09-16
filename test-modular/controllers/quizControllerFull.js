// =================================================================
// QUIZ CONTROLLER - Gestão completa do sistema de quiz
// =================================================================

const db = require('../config/database');

// =================================================================
// OBTER TEMAS DISPONÍVEIS
// =================================================================
async function getThemes(req, res) {
    try {
        const query = `
            SELECT DISTINCT theme, COUNT(*) as question_count
            FROM questions 
            WHERE theme IS NOT NULL AND theme != ''
            GROUP BY theme 
            ORDER BY theme
        `;

        const result = await db.query(query);
        
        const themes = result.rows.map(row => ({
            theme: row.theme,
            question_count: parseInt(row.question_count)
        }));

        res.json({
            themes,
            total_themes: themes.length
        });

    } catch (error) {
        console.error('❌ Erro ao obter temas:', error);
        res.status(500).json({ 
            error: 'Erro interno do servidor' 
        });
    }
}

// =================================================================
// OBTER QUESTÕES PARA QUIZ
// =================================================================
async function getQuestions(req, res) {
    try {
        const { theme, difficulty, count = 10 } = req.body;
        
        let query = 'SELECT * FROM questions WHERE 1=1';
        let params = [];
        let paramIndex = 1;

        // Filtrar por tema
        if (theme && theme !== 'all') {
            query += ` AND theme = $${paramIndex}`;
            params.push(theme);
            paramIndex++;
        }

        // Filtrar por dificuldade
        if (difficulty && difficulty !== 'all') {
            query += ` AND difficulty = $${paramIndex}`;
            params.push(difficulty);
            paramIndex++;
        }

        // Adicionar randomização e limite
        query += ` ORDER BY RANDOM() LIMIT $${paramIndex}`;
        params.push(parseInt(count));

        const result = await db.query(query, params);

        // Processar questões para remover a resposta correta
        const questions = result.rows.map(q => ({
            id: q.id,
            question: q.question,
            options: [q.option_a, q.option_b, q.option_c, q.option_d],
            theme: q.theme,
            difficulty: q.difficulty,
            image_url: q.image_url
        }));

        console.log(`✅ ${questions.length} questões enviadas - Tema: ${theme || 'todos'}, Dificuldade: ${difficulty || 'todas'}`);

        res.json({
            questions,
            count: questions.length,
            theme: theme || 'all',
            difficulty: difficulty || 'all'
        });

    } catch (error) {
        console.error('❌ Erro ao obter questões:', error);
        res.status(500).json({ 
            error: 'Erro interno do servidor' 
        });
    }
}

// =================================================================
// CONTAGEM DE QUESTÕES
// =================================================================
async function getQuestionsCount(req, res) {
    try {
        const { theme, difficulty } = req.body || req.query;
        
        let query = 'SELECT COUNT(*) as count FROM questions WHERE 1=1';
        let params = [];
        let paramIndex = 1;

        if (theme && theme !== 'all') {
            query += ` AND theme = $${paramIndex}`;
            params.push(theme);
            paramIndex++;
        }

        if (difficulty && difficulty !== 'all') {
            query += ` AND difficulty = $${paramIndex}`;
            params.push(difficulty);
            paramIndex++;
        }

        const result = await db.query(query, params);
        const count = parseInt(result.rows[0].count);

        res.json({
            count,
            theme: theme || 'all',
            difficulty: difficulty || 'all'
        });

    } catch (error) {
        console.error('❌ Erro ao contar questões:', error);
        res.status(500).json({ 
            error: 'Erro interno do servidor' 
        });
    }
}

// =================================================================
// CONTAGEM POR TEMA
// =================================================================
async function getCountsByTheme(req, res) {
    try {
        const query = `
            SELECT 
                theme,
                COUNT(*) as total,
                COUNT(CASE WHEN difficulty = 'easy' THEN 1 END) as easy,
                COUNT(CASE WHEN difficulty = 'medium' THEN 1 END) as medium,
                COUNT(CASE WHEN difficulty = 'hard' THEN 1 END) as hard
            FROM questions 
            WHERE theme IS NOT NULL AND theme != ''
            GROUP BY theme 
            ORDER BY theme
        `;

        const result = await db.query(query);
        
        const counts = result.rows.map(row => ({
            theme: row.theme,
            total: parseInt(row.total),
            easy: parseInt(row.easy),
            medium: parseInt(row.medium),
            hard: parseInt(row.hard)
        }));

        res.json({
            counts_by_theme: counts
        });

    } catch (error) {
        console.error('❌ Erro ao obter contagens por tema:', error);
        res.status(500).json({ 
            error: 'Erro interno do servidor' 
        });
    }
}

// =================================================================
// FINALIZAR QUIZ
// =================================================================
async function finishQuiz(req, res) {
    try {
        const userId = req.user.userId;
        const { 
            theme, 
            total_questions, 
            correct_answers, 
            time_taken, 
            answers 
        } = req.body;

        if (!theme || !total_questions || correct_answers === undefined) {
            return res.status(400).json({ 
                error: 'Dados do quiz incompletos' 
            });
        }

        const percentage = (correct_answers / total_questions) * 100;

        // Salvar histórico do quiz
        const insertQuery = `
            INSERT INTO quiz_history (
                user_id, theme, total_questions, correct_answers, 
                percentage, time_taken, answers, created_at
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, NOW())
            RETURNING id, created_at
        `;

        const result = await db.query(insertQuery, [
            userId, theme, total_questions, correct_answers,
            percentage, time_taken, JSON.stringify(answers)
        ]);

        console.log(`✅ Quiz finalizado - Usuário: ${userId}, Tema: ${theme}, Score: ${percentage.toFixed(1)}%`);

        res.json({
            message: 'Quiz finalizado com sucesso',
            quiz_id: result.rows[0].id,
            results: {
                theme,
                total_questions,
                correct_answers,
                percentage: parseFloat(percentage.toFixed(2)),
                time_taken,
                completed_at: result.rows[0].created_at
            }
        });

    } catch (error) {
        console.error('❌ Erro ao finalizar quiz:', error);
        res.status(500).json({ 
            error: 'Erro interno do servidor' 
        });
    }
}

// =================================================================
// HISTÓRICO DE QUIZZES
// =================================================================
async function getHistory(req, res) {
    try {
        const userId = req.user.userId;
        const { limit = 50, offset = 0 } = req.query;

        const query = `
            SELECT id, theme, total_questions, correct_answers, 
                   percentage, time_taken, created_at
            FROM quiz_history 
            WHERE user_id = $1 
            ORDER BY created_at DESC 
            LIMIT $2 OFFSET $3
        `;

        const countQuery = `
            SELECT COUNT(*) as total 
            FROM quiz_history 
            WHERE user_id = $1
        `;

        const [historyResult, countResult] = await Promise.all([
            db.query(query, [userId, limit, offset]),
            db.query(countQuery, [userId])
        ]);

        const history = historyResult.rows.map(quiz => ({
            id: quiz.id,
            theme: quiz.theme,
            total_questions: quiz.total_questions,
            correct_answers: quiz.correct_answers,
            percentage: parseFloat(quiz.percentage),
            time_taken: quiz.time_taken,
            completed_at: quiz.created_at
        }));

        res.json({
            history,
            pagination: {
                total: parseInt(countResult.rows[0].total),
                limit: parseInt(limit),
                offset: parseInt(offset),
                has_more: (parseInt(offset) + parseInt(limit)) < parseInt(countResult.rows[0].total)
            }
        });

    } catch (error) {
        console.error('❌ Erro ao obter histórico:', error);
        res.status(500).json({ 
            error: 'Erro interno do servidor' 
        });
    }
}

// =================================================================
// DETALHES DE UM QUIZ ESPECÍFICO
// =================================================================
async function getQuizDetails(req, res) {
    try {
        const userId = req.user.userId;
        const { id } = req.params;

        const query = `
            SELECT * FROM quiz_history 
            WHERE id = $1 AND user_id = $2
        `;

        const result = await db.query(query, [id, userId]);

        if (result.rows.length === 0) {
            return res.status(404).json({ 
                error: 'Quiz não encontrado' 
            });
        }

        const quiz = result.rows[0];

        res.json({
            quiz: {
                id: quiz.id,
                theme: quiz.theme,
                total_questions: quiz.total_questions,
                correct_answers: quiz.correct_answers,
                percentage: parseFloat(quiz.percentage),
                time_taken: quiz.time_taken,
                answers: quiz.answers,
                completed_at: quiz.created_at
            }
        });

    } catch (error) {
        console.error('❌ Erro ao obter detalhes do quiz:', error);
        res.status(500).json({ 
            error: 'Erro interno do servidor' 
        });
    }
}

// =================================================================
// REPORTAR ERRO EM QUESTÃO
// =================================================================
async function reportError(req, res) {
    try {
        const userId = req.user.userId;
        const { question_id, error_type, description } = req.body;

        if (!question_id || !error_type) {
            return res.status(400).json({ 
                error: 'ID da questão e tipo de erro são obrigatórios' 
            });
        }

        // Verificar se questão existe
        const questionExists = await db.query(
            'SELECT id FROM questions WHERE id = $1',
            [question_id]
        );

        if (questionExists.rows.length === 0) {
            return res.status(404).json({ 
                error: 'Questão não encontrada' 
            });
        }

        // Inserir reporte de erro
        const insertQuery = `
            INSERT INTO error_reports (
                user_id, question_id, error_type, description, 
                status, created_at
            ) VALUES ($1, $2, $3, $4, 'pending', NOW())
            RETURNING id
        `;

        const result = await db.query(insertQuery, [
            userId, question_id, error_type, description
        ]);

        console.log(`📋 Erro reportado - Questão: ${question_id}, Tipo: ${error_type}, Usuário: ${userId}`);

        res.json({
            message: 'Erro reportado com sucesso',
            report_id: result.rows[0].id,
            status: 'pending'
        });

    } catch (error) {
        console.error('❌ Erro ao reportar erro:', error);
        res.status(500).json({ 
            error: 'Erro interno do servidor' 
        });
    }
}

// =================================================================
// REPORTAR ERRO COM CORREÇÃO SUGERIDA
// =================================================================
async function reportErrorWithCorrection(req, res) {
    try {
        const userId = req.user.userId;
        const { 
            question_id, 
            error_type, 
            description, 
            suggested_question,
            suggested_options,
            suggested_correct_answer 
        } = req.body;

        if (!question_id || !error_type) {
            return res.status(400).json({ 
                error: 'ID da questão e tipo de erro são obrigatórios' 
            });
        }

        // Inserir reporte com correção
        const insertQuery = `
            INSERT INTO error_reports (
                user_id, question_id, error_type, description,
                suggested_question, suggested_options, suggested_correct_answer,
                status, created_at
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, 'pending', NOW())
            RETURNING id
        `;

        const result = await db.query(insertQuery, [
            userId, question_id, error_type, description,
            suggested_question, JSON.stringify(suggested_options), suggested_correct_answer
        ]);

        console.log(`📋 Erro com correção reportado - Questão: ${question_id}, Usuário: ${userId}`);

        res.json({
            message: 'Erro com correção reportado com sucesso',
            report_id: result.rows[0].id,
            status: 'pending'
        });

    } catch (error) {
        console.error('❌ Erro ao reportar erro com correção:', error);
        res.status(500).json({ 
            error: 'Erro interno do servidor' 
        });
    }
}

module.exports = {
    getThemes,
    getQuestions,
    getQuestionsCount,
    getCountsByTheme,
    finishQuiz,
    getHistory,
    getQuizDetails,
    reportError,
    reportErrorWithCorrection
};
