const express = require('express');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');
const path = require('path');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 4000;

// Middleware
app.use(cors({
    origin: ['http://localhost:8080', 'http://localhost:3000', process.env.FRONTEND_URL],
    credentials: true
}));
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Database Configuration
const pool = new Pool({
    host: process.env.DB_HOST || 'localhost',
    port: process.env.DB_PORT || 5432,
    database: process.env.DB_NAME || 'quiz_system',
    user: process.env.DB_USER || 'postgres',
    password: process.env.DB_PASSWORD,
    ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false,
    max: 20,
    idleTimeoutMillis: 30000,
    connectionTimeoutMillis: 2000,
});

// JWT Secret
const JWT_SECRET = process.env.JWT_SECRET || 'quiz-secret-key-2024';

// Auth Middleware
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ error: 'Token de acesso requerido' });
    }

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            return res.status(403).json({ error: 'Token inválido' });
        }
        req.user = user;
        next();
    });
};

// Admin Middleware
const requireAdmin = (req, res, next) => {
    if (!req.user.isAdmin) {
        return res.status(403).json({ error: 'Acesso restrito a administradores' });
    }
    next();
};

// Database Health Check
app.get('/api/health', async (req, res) => {
    try {
        const result = await pool.query('SELECT NOW()');
        res.json({
            status: 'healthy',
            database: 'connected',
            timestamp: result.rows[0].now
        });
    } catch (error) {
        res.status(500).json({
            status: 'unhealthy',
            database: 'disconnected',
            error: error.message
        });
    }
});

// Auth Routes
app.post('/api/auth/login', async (req, res) => {
    try {
        const { email, password } = req.body;

        if (!email || !password) {
            return res.status(400).json({ error: 'Email e senha são obrigatórios' });
        }

        const userQuery = 'SELECT * FROM users WHERE email = $1';
        const userResult = await pool.query(userQuery, [email]);

        if (userResult.rows.length === 0) {
            return res.status(401).json({ error: 'Credenciais inválidas' });
        }

        const user = userResult.rows[0];
        const validPassword = await bcrypt.compare(password, user.password);

        if (!validPassword) {
            return res.status(401).json({ error: 'Credenciais inválidas' });
        }

        const token = jwt.sign(
            { 
                id: user.id, 
                email: user.email, 
                name: user.name,
                isAdmin: user.is_admin || false
            },
            JWT_SECRET,
            { expiresIn: '24h' }
        );

        res.json({
            token,
            user: {
                id: user.id,
                email: user.email,
                name: user.name,
                isAdmin: user.is_admin || false
            }
        });
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ error: 'Erro interno do servidor' });
    }
});

app.post('/api/auth/signup', async (req, res) => {
    try {
        const { name, email, password } = req.body;

        if (!name || !email || !password) {
            return res.status(400).json({ error: 'Nome, email e senha são obrigatórios' });
        }

        // Check if user exists
        const existingUser = await pool.query('SELECT id FROM users WHERE email = $1', [email]);
        if (existingUser.rows.length > 0) {
            return res.status(400).json({ error: 'Email já cadastrado' });
        }

        // Hash password
        const saltRounds = 10;
        const hashedPassword = await bcrypt.hash(password, saltRounds);

        // Create user
        const insertQuery = `
            INSERT INTO users (name, email, password, created_at) 
            VALUES ($1, $2, $3, NOW()) 
            RETURNING id, name, email
        `;
        const newUser = await pool.query(insertQuery, [name, email, hashedPassword]);
        const user = newUser.rows[0];

        const token = jwt.sign(
            { 
                id: user.id, 
                email: user.email, 
                name: user.name,
                isAdmin: false
            },
            JWT_SECRET,
            { expiresIn: '24h' }
        );

        res.status(201).json({
            token,
            user: {
                id: user.id,
                email: user.email,
                name: user.name,
                isAdmin: false
            }
        });
    } catch (error) {
        console.error('Signup error:', error);
        res.status(500).json({ error: 'Erro interno do servidor' });
    }
});

// Quiz Routes
app.get('/api/quiz/themes', async (req, res) => {
    try {
        const query = `
            SELECT 
                themes.id,
                themes.name as title,
                COALESCE(themes.description, '') as summary,
                themes.category_id,
                categories.name as category_name,
                COUNT(questions.id) as question_count
            FROM themes 
            LEFT JOIN categories ON themes.category_id = categories.id
            LEFT JOIN questions ON themes.id = questions.theme_id
            WHERE themes.active = true
            GROUP BY themes.id, themes.name, themes.description, themes.category_id, categories.name
            ORDER BY themes.name
        `;
        
        const result = await pool.query(query);
        res.json(result.rows);
    } catch (error) {
        console.error('Error fetching themes:', error);
        res.status(500).json({ error: 'Erro ao buscar temas' });
    }
});

app.get('/api/quiz/themes/:themeId/questions', async (req, res) => {
    try {
        const { themeId } = req.params;
        const limit = parseInt(req.query.limit) || 10;

        const query = `
            SELECT 
                id,
                question_text as text,
                option_a,
                option_b,
                option_c,
                option_d,
                correct_answer,
                difficulty,
                explanation
            FROM questions 
            WHERE theme_id = $1 AND active = true
            ORDER BY RANDOM()
            LIMIT $2
        `;
        
        const result = await pool.query(query, [themeId, limit]);
        res.json(result.rows);
    } catch (error) {
        console.error('Error fetching questions:', error);
        res.status(500).json({ error: 'Erro ao buscar questões' });
    }
});

// Performance Routes
app.post('/api/quiz/submit', authenticateToken, async (req, res) => {
    try {
        const { themeId, answers, score, totalQuestions } = req.body;
        const userId = req.user.id;

        const insertQuery = `
            INSERT INTO quiz_results (user_id, theme_id, score, total_questions, answers, completed_at)
            VALUES ($1, $2, $3, $4, $5, NOW())
            RETURNING id
        `;
        
        const result = await pool.query(insertQuery, [
            userId, 
            themeId, 
            score, 
            totalQuestions, 
            JSON.stringify(answers)
        ]);

        res.json({
            success: true,
            resultId: result.rows[0].id,
            score,
            percentage: Math.round((score / totalQuestions) * 100)
        });
    } catch (error) {
        console.error('Error submitting quiz:', error);
        res.status(500).json({ error: 'Erro ao salvar resultado' });
    }
});

app.get('/api/quiz/results', authenticateToken, async (req, res) => {
    try {
        const userId = req.user.id;
        
        const query = `
            SELECT 
                qr.id,
                qr.score,
                qr.total_questions,
                qr.completed_at,
                t.name as theme_name,
                ROUND((qr.score::decimal / qr.total_questions) * 100, 1) as percentage
            FROM quiz_results qr
            JOIN themes t ON qr.theme_id = t.id
            WHERE qr.user_id = $1
            ORDER BY qr.completed_at DESC
            LIMIT 50
        `;
        
        const result = await pool.query(query, [userId]);
        res.json(result.rows);
    } catch (error) {
        console.error('Error fetching results:', error);
        res.status(500).json({ error: 'Erro ao buscar resultados' });
    }
});

// Admin Routes
app.get('/api/admin/stats', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const statsQueries = await Promise.all([
            pool.query('SELECT COUNT(*) as total_users FROM users'),
            pool.query('SELECT COUNT(*) as total_themes FROM themes WHERE active = true'),
            pool.query('SELECT COUNT(*) as total_questions FROM questions WHERE active = true'),
            pool.query('SELECT COUNT(*) as total_results FROM quiz_results'),
            pool.query(`
                SELECT 
                    t.name as theme_name,
                    COUNT(qr.id) as attempts,
                    ROUND(AVG(qr.score::decimal / qr.total_questions * 100), 1) as avg_score
                FROM themes t
                LEFT JOIN quiz_results qr ON t.id = qr.theme_id
                WHERE t.active = true
                GROUP BY t.id, t.name
                ORDER BY attempts DESC
                LIMIT 10
            `)
        ]);

        res.json({
            totalUsers: parseInt(statsQueries[0].rows[0].total_users),
            totalThemes: parseInt(statsQueries[1].rows[0].total_themes),
            totalQuestions: parseInt(statsQueries[2].rows[0].total_questions),
            totalResults: parseInt(statsQueries[3].rows[0].total_results),
            popularThemes: statsQueries[4].rows
        });
    } catch (error) {
        console.error('Error fetching admin stats:', error);
        res.status(500).json({ error: 'Erro ao buscar estatísticas' });
    }
});

// Error handling middleware
app.use((err, req, res, next) => {
    console.error('Unhandled error:', err);
    res.status(500).json({ error: 'Erro interno do servidor' });
});

// Graceful shutdown
process.on('SIGINT', async () => {
    console.log('\n🔄 Shutting down gracefully...');
    await pool.end();
    console.log('💤 Database connections closed');
    process.exit(0);
});

// Start server
app.listen(PORT, () => {
    console.log(`🚀 Production server running on http://localhost:${PORT}`);
    console.log(`📊 Environment: ${process.env.NODE_ENV || 'development'}`);
    console.log(`🔗 Database: ${process.env.DB_NAME || 'quiz_system'}`);
    console.log('⚡ Ready for production use!');
});

module.exports = app;
