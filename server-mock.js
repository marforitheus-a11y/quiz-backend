const express = require('express');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const app = express();
const PORT = process.env.PORT || 4000;

// Middleware
app.use(cors({
    origin: ['http://localhost:8080', 'http://localhost:3000'],
    credentials: true
}));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// JWT Secret
const JWT_SECRET = process.env.JWT_SECRET || 'quiz-secret-key-2024';

// Mock data (baseado no seu db.json real)
const mockUsers = new Map();
const mockResults = new Map();

// Mock themes data (usando a estrutura real do seu banco)
const mockThemes = [
    { id: 1, title: "Administração Pública", summary: "Conceitos básicos de administração pública", category_id: 1, category_name: "Direito", question_count: 25 },
    { id: 2, title: "Direito Constitucional", summary: "Princípios e normas constitucionais", category_id: 1, category_name: "Direito", question_count: 30 },
    { id: 3, title: "Direito Administrativo", summary: "Atos e processos administrativos", category_id: 1, category_name: "Direito", question_count: 22 },
    { id: 4, title: "Direito Penal", summary: "Crimes e suas punições", category_id: 1, category_name: "Direito", question_count: 18 },
    { id: 5, title: "Direito Processual Penal", summary: "Procedimentos penais", category_id: 1, category_name: "Direito", question_count: 15 },
    { id: 6, title: "Matemática", summary: "Conceitos matemáticos fundamentais", category_id: 2, category_name: "Exatas", question_count: 40 },
    { id: 7, title: "Português", summary: "Gramática e interpretação", category_id: 3, category_name: "Línguas", question_count: 35 },
    { id: 8, title: "Informática", summary: "Conhecimentos básicos de informática", category_id: 4, category_name: "Tecnologia", question_count: 20 }
];

const mockQuestions = [
    {
        id: 1,
        text: "Qual é o princípio fundamental da administração pública?",
        option_a: "Eficiência",
        option_b: "Legalidade",
        option_c: "Moralidade",
        option_d: "Publicidade",
        correct_answer: "B",
        difficulty: "medium",
        explanation: "A legalidade é o princípio basilar que rege toda a administração pública."
    },
    {
        id: 2,
        text: "O que caracteriza um ato administrativo?",
        option_a: "Presunção de legitimidade",
        option_b: "Imperatividade",
        option_c: "Autoexecutoriedade",
        option_d: "Todas as anteriores",
        correct_answer: "D",
        difficulty: "medium",
        explanation: "Atos administrativos possuem presunção de legitimidade, imperatividade e autoexecutoriedade."
    }
];

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

// Health Check
app.get('/api/health', (req, res) => {
    res.json({
        status: 'healthy',
        database: 'mock_data',
        timestamp: new Date().toISOString()
    });
});

// Auth Routes
app.post('/api/auth/signup', async (req, res) => {
    try {
        const { name, email, password } = req.body;

        if (!name || !email || !password) {
            return res.status(400).json({ error: 'Nome, email e senha são obrigatórios' });
        }

        if (mockUsers.has(email)) {
            return res.status(400).json({ error: 'Email já cadastrado' });
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        const user = { 
            id: Date.now(), 
            name, 
            email, 
            password: hashedPassword, 
            isAdmin: false 
        };
        
        mockUsers.set(email, user);

        const token = jwt.sign(
            { id: user.id, email: user.email, name: user.name, isAdmin: user.isAdmin },
            JWT_SECRET,
            { expiresIn: '24h' }
        );

        res.status(201).json({
            token,
            user: { id: user.id, email: user.email, name: user.name, isAdmin: user.isAdmin }
        });
    } catch (error) {
        console.error('Signup error:', error);
        res.status(500).json({ error: 'Erro interno do servidor' });
    }
});

app.post('/api/auth/login', async (req, res) => {
    try {
        const { email, password } = req.body;

        if (!email || !password) {
            return res.status(400).json({ error: 'Email e senha são obrigatórios' });
        }

        const user = mockUsers.get(email);
        if (!user) {
            return res.status(401).json({ error: 'Credenciais inválidas' });
        }

        const validPassword = await bcrypt.compare(password, user.password);
        if (!validPassword) {
            return res.status(401).json({ error: 'Credenciais inválidas' });
        }

        const token = jwt.sign(
            { id: user.id, email: user.email, name: user.name, isAdmin: user.isAdmin },
            JWT_SECRET,
            { expiresIn: '24h' }
        );

        res.json({
            token,
            user: { id: user.id, email: user.email, name: user.name, isAdmin: user.isAdmin }
        });
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ error: 'Erro interno do servidor' });
    }
});

// Quiz Routes
app.get('/api/quiz/themes', (req, res) => {
    res.json(mockThemes);
});

app.get('/api/quiz/themes/:themeId/questions', (req, res) => {
    const { themeId } = req.params;
    const limit = parseInt(req.query.limit) || 10;
    
    // Return mock questions (você pode expandir isso)
    const questions = mockQuestions.slice(0, limit);
    res.json(questions);
});

app.post('/api/quiz/submit', authenticateToken, (req, res) => {
    const { themeId, answers, score, totalQuestions } = req.body;
    const userId = req.user.id;

    const result = {
        id: Date.now(),
        user_id: userId,
        theme_id: themeId,
        score,
        total_questions: totalQuestions,
        answers,
        completed_at: new Date().toISOString()
    };

    if (!mockResults.has(userId)) {
        mockResults.set(userId, []);
    }
    mockResults.get(userId).push(result);

    res.json({
        success: true,
        resultId: result.id,
        score,
        percentage: Math.round((score / totalQuestions) * 100)
    });
});

app.get('/api/quiz/results', authenticateToken, (req, res) => {
    const userId = req.user.id;
    const userResults = mockResults.get(userId) || [];
    
    const formattedResults = userResults.map(result => {
        const theme = mockThemes.find(t => t.id == result.theme_id);
        return {
            id: result.id,
            score: result.score,
            total_questions: result.total_questions,
            completed_at: result.completed_at,
            theme_name: theme ? theme.title : 'Tema não encontrado',
            percentage: Math.round((result.score / result.total_questions) * 100)
        };
    });

    res.json(formattedResults);
});

// Start server
const server = app.listen(PORT, () => {
    console.log(`🚀 Mock Production Server running on http://localhost:${PORT}`);
    console.log(`📊 Mode: Mock Data (Database Independent)`);
    console.log(`🎯 ${mockThemes.length} themes available`);
    console.log('⚡ Ready for frontend testing!');
    console.log('\n💡 Para conectar ao banco real, configure o PostgreSQL e use server-production.js');
});

// Graceful shutdown
process.on('SIGINT', () => {
    console.log('\n🔄 Shutting down gracefully...');
    server.close(() => {
        console.log('💤 Server closed');
        process.exit(0);
    });
});

module.exports = app;
