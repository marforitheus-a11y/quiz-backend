// =================================================================
// ADMIN CONTROLLER - Gestão administrativa completa
// =================================================================

const db = require('../config/database');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const { GoogleGenerativeAI } = require("@google/generative-ai");

const genAI = new GoogleGenerativeAI(process.env.GEMINI_API_KEY);

// =================================================================
// MIDDLEWARE DE AUTORIZAÇÃO ADMIN
// =================================================================
function authorizeAdmin(req, res, next) {
    if (!req.user.is_admin) {
        return res.status(403).json({ 
            error: 'Acesso negado. Apenas administradores.' 
        });
    }
    next();
}

// =================================================================
// BROADCAST DE MENSAGENS
// =================================================================
let globalMessage = null;

async function broadcast(req, res) {
    try {
        const { message, type = 'info' } = req.body;
        
        if (!message) {
            return res.status(400).json({ 
                error: 'Mensagem é obrigatória' 
            });
        }

        globalMessage = {
            message,
            type,
            timestamp: new Date().toISOString(),
            admin: req.user.username
        };

        console.log(`📢 Broadcast enviado por ${req.user.username}: ${message}`);

        res.json({
            message: 'Broadcast enviado com sucesso',
            broadcast: globalMessage
        });

    } catch (error) {
        console.error('❌ Erro no broadcast:', error);
        res.status(500).json({ 
            error: 'Erro interno do servidor' 
        });
    }
}

function getMessage(req, res) {
    res.json({
        message: globalMessage
    });
}

function setMessage(req, res) {
    const { message } = req.body;
    
    globalMessage = message ? {
        message,
        type: 'info',
        timestamp: new Date().toISOString(),
        admin: req.user.username
    } : null;

    res.json({
        message: 'Mensagem global definida',
        global_message: globalMessage
    });
}

// =================================================================
// GESTÃO DE USUÁRIOS
// =================================================================
async function getUsers(req, res) {
    try {
        const { page = 1, limit = 50, search = '' } = req.query;
        const offset = (page - 1) * limit;

        let query = `
            SELECT id, username, email, is_admin, created_at,
                   gdpr_consent_date, account_deletion_requested,
                   account_deletion_scheduled
            FROM users 
            WHERE 1=1
        `;
        let params = [];
        let paramIndex = 1;

        if (search) {
            query += ` AND (username ILIKE $${paramIndex} OR email ILIKE $${paramIndex})`;
            params.push(`%${search}%`);
            paramIndex++;
        }

        query += ` ORDER BY created_at DESC LIMIT $${paramIndex} OFFSET $${paramIndex + 1}`;
        params.push(limit, offset);

        const countQuery = `
            SELECT COUNT(*) as total FROM users 
            WHERE ${search ? '(username ILIKE $1 OR email ILIKE $1)' : '1=1'}
        `;
        
        const [usersResult, countResult] = await Promise.all([
            db.query(query, params),
            db.query(countQuery, search ? [`%${search}%`] : [])
        ]);

        const users = usersResult.rows.map(user => ({
            id: user.id,
            username: user.username,
            email: user.email,
            is_admin: user.is_admin,
            created_at: user.created_at,
            gdpr_consent_date: user.gdpr_consent_date,
            account_deletion_requested: user.account_deletion_requested,
            account_deletion_scheduled: user.account_deletion_scheduled
        }));

        res.json({
            users,
            pagination: {
                total: parseInt(countResult.rows[0].total),
                page: parseInt(page),
                limit: parseInt(limit),
                pages: Math.ceil(countResult.rows[0].total / limit)
            }
        });

    } catch (error) {
        console.error('❌ Erro ao obter usuários:', error);
        res.status(500).json({ 
            error: 'Erro interno do servidor' 
        });
    }
}

async function updateUser(req, res) {
    try {
        const { id } = req.params;
        const { username, email, is_admin } = req.body;

        if (!username || !email) {
            return res.status(400).json({ 
                error: 'Username e email são obrigatórios' 
            });
        }

        // Verificar se usuário existe
        const userExists = await db.query(
            'SELECT id FROM users WHERE id = $1',
            [id]
        );

        if (userExists.rows.length === 0) {
            return res.status(404).json({ 
                error: 'Usuário não encontrado' 
            });
        }

        // Verificar se username ou email já existem
        const duplicateCheck = await db.query(
            'SELECT id FROM users WHERE (username = $1 OR email = $2) AND id != $3',
            [username, email, id]
        );

        if (duplicateCheck.rows.length > 0) {
            return res.status(409).json({ 
                error: 'Username ou email já existem' 
            });
        }

        // Atualizar usuário
        const updateQuery = `
            UPDATE users 
            SET username = $1, email = $2, is_admin = $3
            WHERE id = $4
            RETURNING id, username, email, is_admin, created_at
        `;

        const result = await db.query(updateQuery, [
            username, email, is_admin || false, id
        ]);

        console.log(`✅ Usuário atualizado por admin ${req.user.username}: ${username} (ID: ${id})`);

        res.json({
            message: 'Usuário atualizado com sucesso',
            user: result.rows[0]
        });

    } catch (error) {
        console.error('❌ Erro ao atualizar usuário:', error);
        res.status(500).json({ 
            error: 'Erro interno do servidor' 
        });
    }
}

async function deleteUser(req, res) {
    try {
        const { id } = req.params;

        // Não permitir que admin delete a si mesmo
        if (parseInt(id) === req.user.userId) {
            return res.status(400).json({ 
                error: 'Você não pode deletar sua própria conta' 
            });
        }

        // Verificar se usuário existe
        const userQuery = await db.query(
            'SELECT username FROM users WHERE id = $1',
            [id]
        );

        if (userQuery.rows.length === 0) {
            return res.status(404).json({ 
                error: 'Usuário não encontrado' 
            });
        }

        const username = userQuery.rows[0].username;

        // Deletar usuário (CASCADE deve deletar dados relacionados)
        await db.query('DELETE FROM users WHERE id = $1', [id]);

        console.log(`⚠️ Usuário deletado por admin ${req.user.username}: ${username} (ID: ${id})`);

        res.json({
            message: 'Usuário deletado com sucesso',
            deleted_user: username
        });

    } catch (error) {
        console.error('❌ Erro ao deletar usuário:', error);
        res.status(500).json({ 
            error: 'Erro interno do servidor' 
        });
    }
}

// =================================================================
// SESSÕES ATIVAS
// =================================================================
let activeSessions = {};

function getSessions(req, res) {
    const sessions = Object.keys(activeSessions).map(sessionId => ({
        session_id: sessionId,
        ...activeSessions[sessionId]
    }));

    res.json({
        active_sessions: sessions,
        total: sessions.length
    });
}

// =================================================================
// RELATÓRIOS DE ERRO
// =================================================================
async function getReports(req, res) {
    try {
        const { status = 'all', page = 1, limit = 50 } = req.query;
        const offset = (page - 1) * limit;

        let query = `
            SELECT er.*, u.username, q.question
            FROM error_reports er
            LEFT JOIN users u ON er.user_id = u.id
            LEFT JOIN questions q ON er.question_id = q.id
            WHERE 1=1
        `;
        let params = [];
        let paramIndex = 1;

        if (status !== 'all') {
            query += ` AND er.status = $${paramIndex}`;
            params.push(status);
            paramIndex++;
        }

        query += ` ORDER BY er.created_at DESC LIMIT $${paramIndex} OFFSET $${paramIndex + 1}`;
        params.push(limit, offset);

        const result = await db.query(query, params);

        const reports = result.rows.map(report => ({
            id: report.id,
            question_id: report.question_id,
            user_id: report.user_id,
            username: report.username,
            error_type: report.error_type,
            description: report.description,
            question_preview: report.question ? report.question.substring(0, 100) + '...' : null,
            status: report.status,
            suggested_question: report.suggested_question,
            suggested_options: report.suggested_options,
            suggested_correct_answer: report.suggested_correct_answer,
            created_at: report.created_at
        }));

        res.json({
            reports,
            pagination: {
                page: parseInt(page),
                limit: parseInt(limit),
                total: reports.length
            }
        });

    } catch (error) {
        console.error('❌ Erro ao obter relatórios:', error);
        res.status(500).json({ 
            error: 'Erro interno do servidor' 
        });
    }
}

// =================================================================
// DASHBOARD E MÉTRICAS
// =================================================================
async function getDashboard(req, res) {
    try {
        const metricsQuery = `
            SELECT 
                (SELECT COUNT(*) FROM users) as total_users,
                (SELECT COUNT(*) FROM users WHERE created_at > NOW() - INTERVAL '30 days') as new_users_month,
                (SELECT COUNT(*) FROM questions) as total_questions,
                (SELECT COUNT(*) FROM quiz_history) as total_quizzes,
                (SELECT COUNT(*) FROM quiz_history WHERE created_at > NOW() - INTERVAL '30 days') as quizzes_month,
                (SELECT AVG(percentage) FROM quiz_history) as average_score,
                (SELECT COUNT(*) FROM error_reports WHERE status = 'pending') as pending_reports,
                (SELECT COUNT(DISTINCT theme) FROM questions) as total_themes
        `;

        const result = await db.query(metricsQuery);
        const metrics = result.rows[0];

        // Top temas
        const topThemesQuery = `
            SELECT theme, COUNT(*) as plays
            FROM quiz_history 
            WHERE created_at > NOW() - INTERVAL '30 days'
            GROUP BY theme 
            ORDER BY plays DESC 
            LIMIT 10
        `;

        const topThemes = await db.query(topThemesQuery);

        // Usuários mais ativos
        const activeUsersQuery = `
            SELECT u.username, COUNT(qh.id) as quizzes_count
            FROM users u
            LEFT JOIN quiz_history qh ON u.id = qh.user_id
            WHERE qh.created_at > NOW() - INTERVAL '30 days'
            GROUP BY u.id, u.username
            ORDER BY quizzes_count DESC
            LIMIT 10
        `;

        const activeUsers = await db.query(activeUsersQuery);

        res.json({
            metrics: {
                total_users: parseInt(metrics.total_users),
                new_users_month: parseInt(metrics.new_users_month),
                total_questions: parseInt(metrics.total_questions),
                total_quizzes: parseInt(metrics.total_quizzes),
                quizzes_month: parseInt(metrics.quizzes_month),
                average_score: parseFloat(metrics.average_score) || 0,
                pending_reports: parseInt(metrics.pending_reports),
                total_themes: parseInt(metrics.total_themes)
            },
            top_themes: topThemes.rows,
            active_users: activeUsers.rows,
            timestamp: new Date().toISOString()
        });

    } catch (error) {
        console.error('❌ Erro ao obter dashboard:', error);
        res.status(500).json({ 
            error: 'Erro interno do servidor' 
        });
    }
}

// =================================================================
// GESTÃO DE QUESTÕES
// =================================================================
async function getQuestions(req, res) {
    try {
        const { page = 1, limit = 50, theme = 'all', difficulty = 'all', search = '' } = req.query;
        const offset = (page - 1) * limit;

        let query = 'SELECT * FROM questions WHERE 1=1';
        let params = [];
        let paramIndex = 1;

        if (theme !== 'all') {
            query += ` AND theme = $${paramIndex}`;
            params.push(theme);
            paramIndex++;
        }

        if (difficulty !== 'all') {
            query += ` AND difficulty = $${paramIndex}`;
            params.push(difficulty);
            paramIndex++;
        }

        if (search) {
            query += ` AND question ILIKE $${paramIndex}`;
            params.push(`%${search}%`);
            paramIndex++;
        }

        query += ` ORDER BY id DESC LIMIT $${paramIndex} OFFSET $${paramIndex + 1}`;
        params.push(limit, offset);

        const result = await db.query(query, params);

        const questions = result.rows.map(q => ({
            id: q.id,
            question: q.question,
            option_a: q.option_a,
            option_b: q.option_b,
            option_c: q.option_c,
            option_d: q.option_d,
            correct_answer: q.correct_answer,
            theme: q.theme,
            difficulty: q.difficulty,
            image_url: q.image_url,
            created_at: q.created_at
        }));

        res.json({
            questions,
            pagination: {
                page: parseInt(page),
                limit: parseInt(limit),
                total: questions.length
            }
        });

    } catch (error) {
        console.error('❌ Erro ao obter questões:', error);
        res.status(500).json({ 
            error: 'Erro interno do servidor' 
        });
    }
}

async function getQuestion(req, res) {
    try {
        const { id } = req.params;

        const query = 'SELECT * FROM questions WHERE id = $1';
        const result = await db.query(query, [id]);

        if (result.rows.length === 0) {
            return res.status(404).json({ 
                error: 'Questão não encontrada' 
            });
        }

        res.json({
            question: result.rows[0]
        });

    } catch (error) {
        console.error('❌ Erro ao obter questão:', error);
        res.status(500).json({ 
            error: 'Erro interno do servidor' 
        });
    }
}

// =================================================================
// CORREÇÃO DE CATEGORIAS COM IA
// =================================================================
async function fixCategories(req, res) {
    try {
        console.log('🔧 Iniciando correção de categorias...');
        
        // Buscar questões sem tema ou com tema inválido
        const questionsQuery = `
            SELECT id, question, theme 
            FROM questions 
            WHERE theme IS NULL OR theme = '' OR theme = 'null'
            LIMIT 50
        `;

        const result = await db.query(questionsQuery);
        const questions = result.rows;

        if (questions.length === 0) {
            return res.json({
                message: 'Nenhuma questão precisa de correção',
                processed: 0
            });
        }

        const model = genAI.getGenerativeModel({ model: "gemini-1.5-flash" });
        let processed = 0;
        let errors = 0;

        for (const question of questions) {
            try {
                const prompt = `
                Analise a seguinte questão e determine o tema/categoria mais apropriado:
                
                Questão: ${question.question}
                
                Categorias disponíveis:
                - Direito Constitucional
                - Direito Administrativo
                - Direito Penal
                - Direito Civil
                - Direito Processual Civil
                - Direito Processual Penal
                - Direito Tributário
                - Direito do Trabalho
                - Direito Empresarial
                - Direito Ambiental
                
                Responda APENAS com o nome da categoria, sem explicações.
                `;

                const aiResult = await model.generateContent(prompt);
                const theme = aiResult.response.text().trim();

                // Atualizar questão
                await db.query(
                    'UPDATE questions SET theme = $1 WHERE id = $2',
                    [theme, question.id]
                );

                processed++;
                console.log(`✅ Questão ${question.id} categorizada como: ${theme}`);

            } catch (aiError) {
                console.error(`❌ Erro na questão ${question.id}:`, aiError);
                errors++;
            }
        }

        console.log(`🏁 Correção concluída - Processadas: ${processed}, Erros: ${errors}`);

        res.json({
            message: 'Correção de categorias concluída',
            processed,
            errors,
            total_found: questions.length
        });

    } catch (error) {
        console.error('❌ Erro na correção de categorias:', error);
        res.status(500).json({ 
            error: 'Erro interno do servidor' 
        });
    }
}

module.exports = {
    authorizeAdmin,
    broadcast,
    getMessage,
    setMessage,
    getUsers,
    updateUser,
    deleteUser,
    getSessions,
    getReports,
    getDashboard,
    getQuestions,
    getQuestion,
    fixCategories
};
