const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const db = require('./db'); // Usa a conexão real com PostgreSQL

const app = express();
const PORT = 4000;
const JWT_SECRET = process.env.JWT_SECRET || 'default_secret_for_testing';

// Middleware
app.use(cors({
    origin: ['http://localhost:8080', 'http://127.0.0.1:8080'],
    credentials: true
}));
app.use(express.json());

// Função para sanitizar questões (do código original)
function sanitizeQuestionRow(row) {
    return {
        id: row.id,
        question: row.question,
        options: row.options,
        answer: row.answer
    };
}

// Middleware de autenticação (simplificado para testes)
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ message: 'Token de acesso necessário' });
    }

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            return res.status(403).json({ message: 'Token inválido' });
        }
        req.user = user;
        next();
    });
}

// ===== ROTAS PRINCIPAIS =====

// Health check
app.get('/health', (req, res) => {
    res.json({ 
        status: 'OK', 
        timestamp: new Date().toISOString(),
        database: 'PostgreSQL (Real Database)',
        server: 'Database-Connected Test Server'
    });
});

// Login simplificado para testes
app.post('/login', async (req, res) => {
    const { username, password } = req.body;
    
    try {
        // Busca usuário na database real
        const result = await db.query('SELECT id, username, password, role, is_pay FROM users WHERE username = $1', [username]);
        
        if (result.rows.length === 0) {
            return res.status(401).json({ message: 'Usuário não encontrado' });
        }
        
        const user = result.rows[0];
        
        // Verifica senha
        const isValidPassword = await bcrypt.compare(password, user.password);
        if (!isValidPassword) {
            return res.status(401).json({ message: 'Senha incorreta' });
        }
        
        // Gera token
        const token = jwt.sign(
            { id: user.id, username: user.username, role: user.role },
            JWT_SECRET,
            { expiresIn: '24h' }
        );
        
        res.json({
            token,
            user: {
                id: user.id,
                username: user.username,
                role: user.role,
                is_pay: user.is_pay
            }
        });
    } catch (err) {
        console.error('Erro no login:', err);
        res.status(500).json({ message: 'Erro interno do servidor' });
    }
});

// Rota de temas - CONECTADA À DATABASE REAL
app.get('/themes', authenticateToken, async (req, res) => {
    try {
        console.log('🔍 Buscando temas da database PostgreSQL...');
        
        // Primeiro, tentar query básica apenas com temas
        let result;
        try {
            result = await db.query(`
                SELECT 
                    themes.id, 
                    themes.title,
                    COUNT(questions.id) as question_count
                FROM themes
                LEFT JOIN questions ON themes.id = questions.theme_id
                GROUP BY themes.id, themes.title
                ORDER BY themes.title
            `);
            console.log(`✅ Query básica: ${result.rows.length} temas encontrados`);
        } catch (basicErr) {
            console.log('❌ Query básica falhou, tentando apenas tabela themes...');
            // Se falhar, tentar apenas a tabela themes
            result = await db.query(`
                SELECT id, title
                FROM themes
                ORDER BY title
            `);
            console.log(`✅ Query simples: ${result.rows.length} temas encontrados`);
            // Adicionar question_count = 0 para compatibilidade
            result.rows = result.rows.map(theme => ({
                ...theme,
                question_count: 0
            }));
        }
        
        // Se encontramos temas, tentar adicionar mais informações
        if (result.rows.length > 0) {
            try {
                // Tentar query completa agora
                const fullResult = await db.query(`
                    SELECT DISTINCT
                        themes.id, 
                        themes.title, 
                        COALESCE(themes.summary, '') as summary,
                        themes.category_id,
                        COALESCE(categories.name, '') as category_name,
                        categories.parent_id as category_parent_id,
                        COUNT(questions.id) as question_count
                    FROM themes
                    LEFT JOIN categories ON themes.category_id = categories.id  
                    LEFT JOIN questions ON themes.id = questions.theme_id
                    GROUP BY themes.id, themes.title, themes.summary, themes.category_id, categories.name, categories.parent_id
                    ORDER BY themes.title
                `);
                console.log(`✅ Query completa bem-sucedida: ${fullResult.rows.length} temas`);
                result = fullResult;
            } catch (fullErr) {
                console.log('⚠️ Query completa falhou, usando dados básicos:', fullErr.message);
                // Usar result básico mesmo
            }
        }
        
        console.log(`📊 Retornando ${result.rows.length} temas para o frontend`);
        res.json(result.rows);
        
    } catch (err) {
        console.error('❌ Erro geral ao buscar temas:', err.message);
        console.error('Stack:', err.stack);
        
        // Tentar auto-fix de colunas faltantes
        if (err.message && err.message.includes('column') && err.message.includes('does not exist')) {
            console.log('🔧 Tentando auto-corrigir estrutura da tabela...');
            try {
                const missingCol = err.message.match(/column "([^"]+)"/)?.[1];
                if (missingCol === 'summary') {
                    await db.query('ALTER TABLE themes ADD COLUMN IF NOT EXISTS summary TEXT');
                } else if (missingCol === 'category_id') {
                    await db.query('ALTER TABLE themes ADD COLUMN IF NOT EXISTS category_id INTEGER NULL');
                }
                console.log(`✅ Coluna ${missingCol} adicionada, tentando novamente...`);
                
                // Retry com query básica
                const retryResult = await db.query(`
                    SELECT id, title, 0 as question_count
                    FROM themes
                    ORDER BY title
                `);
                
                console.log(`✅ Auto-fix bem-sucedido! ${retryResult.rows.length} temas encontrados`);
                return res.json(retryResult.rows);
            } catch (fixErr) {
                console.error('❌ Auto-fix falhou:', fixErr.message);
            }
        }
        
        res.status(500).json({ 
            message: 'Erro ao buscar temas', 
            error: err.message,
            database: 'PostgreSQL',
            stack: err.stack
        });
    }
});

// Rota de questões - CONECTADA À DATABASE REAL
app.post('/questions', authenticateToken, async (req, res) => {
    const { themeIds, count, difficulties } = req.body;
    const userId = req.user.id;

    try {
        console.log(`🔍 Buscando ${count} questões para temas:`, themeIds, 'dificuldades:', difficulties);
        
        // Verificar status de pagamento e limite diário (igual ao original)
        const userResult = await db.query('SELECT is_pay, last_quiz_date, daily_quiz_count FROM users WHERE id = $1', [userId]);
        const user = userResult.rows[0];

        if (!user.is_pay) {
            const today = new Date().toISOString().split('T')[0];
            const lastQuizDate = user.last_quiz_date ? new Date(user.last_quiz_date).toISOString().split('T')[0] : null;

            let dailyCount = user.daily_quiz_count;

            if (today !== lastQuizDate) {
                dailyCount = 0;
                await db.query('UPDATE users SET daily_quiz_count = 0, last_quiz_date = $1 WHERE id = $2', [today, userId]);
            }

            if (dailyCount >= 10) {
                return res.status(403).json({ message: "Você atingiu o limite de 10 questões por dia. Torne-se um usuário VIP para acesso ilimitado." });
            }
        }

        // Query de questões igual ao original
        let qtext = 'SELECT id, question, options, answer FROM questions WHERE theme_id = ANY($1::int[])';
        const params = [themeIds];
        
        if (difficulties && Array.isArray(difficulties) && difficulties.length > 0) {
            params.push(difficulties);
            qtext += ' AND difficulty = ANY($2::text[])';
            qtext += ' ORDER BY RANDOM() LIMIT $3';
            params.push(count);
        } else {
            qtext += ' ORDER BY RANDOM() LIMIT $2';
            params.push(count);
        }
        
        const result = await db.query(qtext, params);
        const sanitized = result.rows.map(r => sanitizeQuestionRow(r));

        console.log(`✅ Encontradas ${sanitized.length} questões`);

        // Atualizar contagem diária para usuários não-pagantes
        if (!user.is_pay) {
            const newCount = (user.daily_quiz_count || 0) + sanitized.length;
            await db.query('UPDATE users SET daily_quiz_count = $1 WHERE id = $2', [newCount, userId]);
        }

        res.json(sanitized);
    } catch (err) {
        console.error("❌ Erro ao buscar questões:", err.message);
        res.status(500).json({ 
            message: 'Erro ao buscar questões',
            error: err.message 
        });
    }
});

// Rota de contagem de questões por dificuldade
app.post('/questions/counts', authenticateToken, async (req, res) => {
    const { themeIds } = req.body;
    
    if (!themeIds || themeIds.length === 0) {
        return res.status(400).json({ message: 'themeIds obrigatório.' });
    }
    
    try {
        const result = await db.query(
            `SELECT COALESCE(difficulty, 'easy') AS difficulty, COUNT(*) AS cnt
             FROM questions WHERE theme_id = ANY($1::int[]) GROUP BY difficulty`,
            [themeIds]
        );
        
        const counts = { easy: 0, medium: 0, hard: 0 };
        for (const row of result.rows) {
            const difficulty = row.difficulty || 'easy';
            counts[difficulty] = parseInt(row.cnt, 10);
        }
        
        res.json(counts);
    } catch (err) {
        console.error('❌ Erro ao contar questões:', err.message);
        res.status(500).json({ message: 'Erro ao contar questões.' });
    }
});

// Finalizar quiz e salvar resultados
app.post('/quiz/finish', authenticateToken, async (req, res) => {
    const { score, totalQuestions, answers } = req.body;
    const userId = req.user.id;
    
    try {
        console.log(`💾 Salvando resultado: ${score}/${totalQuestions} para usuário ${userId}`);
        
        const percentage = totalQuestions > 0 ? ((score / totalQuestions) * 100).toFixed(2) : 0;
        
        // Salvar no histórico (igual ao original)
        const historyResult = await db.query(
            'INSERT INTO quiz_history (user_id, score, total_questions, percentage) VALUES ($1, $2, $3, $4) RETURNING id',
            [userId, score, totalQuestions, percentage]
        );
        
        const newHistoryId = historyResult.rows[0].id;
        
        // Salvar respostas individuais
        for (const answer of answers) {
            await db.query(
                'INSERT INTO user_answers (history_id, question_id, selected_option, is_correct) VALUES ($1, $2, $3, $4)',
                [newHistoryId, answer.questionId, answer.selectedOption, answer.isCorrect]
            );
        }
        
        console.log(`✅ Resultado salvo com ID: ${newHistoryId}`);
        res.status(201).json({ 
            message: "Histórico salvo com sucesso!", 
            historyId: newHistoryId 
        });
    } catch (err) {
        console.error('❌ Erro ao salvar histórico:', err.message);
        res.status(500).json({ message: 'Erro ao salvar histórico.' });
    }
});

// Buscar histórico do usuário
app.get('/history', authenticateToken, async (req, res) => {
    const userId = req.user.id;
    
    try {
        const result = await db.query(
            'SELECT id, score, total_questions, percentage, created_at FROM quiz_history WHERE user_id = $1 ORDER BY created_at DESC',
            [userId]
        );
        
        res.json(result.rows);
    } catch (err) {
        console.error('❌ Erro ao buscar histórico:', err.message);
        res.status(500).json({ message: 'Erro ao buscar histórico.' });
    }
});

// Buscar detalhes de um quiz específico
app.get('/history/:id', authenticateToken, async (req, res) => {
    const { id } = req.params;
    const userId = req.user.id;
    
    try {
        const result = await db.query(`
            SELECT ua.question_id, q.theme_id, q.question, q.options, q.answer as correct_answer, 
                   ua.selected_option, ua.is_correct
            FROM user_answers ua
            JOIN questions q ON ua.question_id = q.id
            JOIN quiz_history qh ON ua.history_id = qh.id
            WHERE ua.history_id = $1 AND qh.user_id = $2
        `, [id, userId]);
        
        if (result.rows.length === 0) {
            return res.status(404).json({ message: "Histórico não encontrado." });
        }
        
        res.json(result.rows);
    } catch (err) {
        console.error('❌ Erro ao buscar detalhes do histórico:', err.message);
        res.status(500).json({ message: 'Erro ao buscar detalhes do histórico.' });
    }
});

// Estatísticas do usuário
app.get('/user/stats', authenticateToken, async (req, res) => {
    const userId = req.user.id;
    
    try {
        const result = await db.query(`
            SELECT 
                COUNT(*) as total_quizzes,
                AVG(CASE WHEN score IS NOT NULL THEN score ELSE 0 END) as avg_score,
                MAX(score) as best_score,
                SUM(CASE WHEN score >= 70 THEN 1 ELSE 0 END) as quizzes_passed
            FROM quiz_history 
            WHERE user_id = $1
        `, [userId]);
        
        const stats = result.rows[0];
        
        res.json({
            totalQuizzes: parseInt(stats.total_quizzes) || 0,
            averageScore: stats.avg_score ? Math.round(parseFloat(stats.avg_score)) : 0,
            bestScore: stats.best_score ? Math.round(parseFloat(stats.best_score)) : 0,
            quizzesPassed: parseInt(stats.quizzes_passed) || 0
        });
    } catch (err) {
        console.error('❌ Erro ao buscar estatísticas:', err.message);
        res.status(500).json({ message: 'Erro ao buscar estatísticas.' });
    }
});

// Iniciar servidor
app.listen(PORT, () => {
    console.log('🚀 =================================');
    console.log(`📡 Servidor TESTE rodando na porta ${PORT}`);
    console.log('🗄️  Conectado à DATABASE REAL PostgreSQL');
    console.log('🔗 Frontend: http://localhost:8080');
    console.log('🔗 Backend:  http://localhost:4000');
    console.log('🧪 Ambiente: TESTE COM DATABASE REAL');
    console.log('   • Temas: PostgreSQL (60+ temas reais)');
    console.log('   • Questões: PostgreSQL (database real)');
    console.log('   • Autenticação: Simplificada para testes');
    console.log('   • Histórico: Salvo na database real');
    console.log('🚀 =================================');
});

module.exports = app;
