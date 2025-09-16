const express = require('express');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const app = express();
const PORT = 4000;

// Middleware
app.use(cors());
app.use(express.json());

// JWT Secret
const JWT_SECRET = 'quiz-secret-2024';

// Mock data baseado no seu sistema real
const users = new Map();
const results = new Map();

const themes = [
    { id: 1, title: "Administração Pública", summary: "Conceitos básicos de administração pública", category_id: 1, category_name: "Direito", question_count: 25 },
    { id: 2, title: "Direito Constitucional", summary: "Princípios e normas constitucionais", category_id: 1, category_name: "Direito", question_count: 30 },
    { id: 3, title: "Direito Administrativo", summary: "Atos e processos administrativos", category_id: 1, category_name: "Direito", question_count: 22 },
    { id: 4, title: "Direito Penal", summary: "Crimes e suas punições", category_id: 1, category_name: "Direito", question_count: 18 },
    { id: 5, title: "Matemática", summary: "Conceitos matemáticos fundamentais", category_id: 2, category_name: "Exatas", question_count: 40 },
    { id: 6, title: "Português", summary: "Gramática e interpretação", category_id: 3, category_name: "Línguas", question_count: 35 },
    { id: 7, title: "Informática", summary: "Conhecimentos básicos de informática", category_id: 4, category_name: "Tecnologia", question_count: 20 },
    { id: 8, title: "História do Brasil", summary: "História do Brasil", category_id: 5, category_name: "Humanas", question_count: 15 }
];

const questions = [
    {
        id: 1, text: "Qual é o princípio fundamental da administração pública?",
        option_a: "Eficiência", option_b: "Legalidade", option_c: "Moralidade", option_d: "Publicidade",
        correct_answer: "B", difficulty: "medium"
    },
    {
        id: 2, text: "Quanto é 2 + 2?",
        option_a: "3", option_b: "4", option_c: "5", option_d: "6",
        correct_answer: "B", difficulty: "easy"
    },
    {
        id: 3, text: "Qual a capital do Brasil?",
        option_a: "São Paulo", option_b: "Rio de Janeiro", option_c: "Brasília", option_d: "Salvador",
        correct_answer: "C", difficulty: "easy"
    }
];

// Auth middleware
const auth = (req, res, next) => {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'Token requerido' });
    
    try {
        req.user = jwt.verify(token, JWT_SECRET);
        next();
    } catch {
        res.status(403).json({ error: 'Token inválido' });
    }
};

// Routes
app.get('/api/health', (req, res) => {
    res.json({ status: 'healthy', timestamp: new Date() });
});

app.post('/api/auth/signup', async (req, res) => {
    const { name, email, password } = req.body;
    
    if (users.has(email)) {
        return res.status(400).json({ error: 'Email já cadastrado' });
    }
    
    const hashedPassword = await bcrypt.hash(password, 10);
    const user = { id: Date.now(), name, email, password: hashedPassword, isAdmin: false };
    users.set(email, user);
    
    const token = jwt.sign({ id: user.id, email, name, isAdmin: false }, JWT_SECRET, { expiresIn: '24h' });
    res.json({ token, user: { id: user.id, email, name, isAdmin: false } });
});

app.post('/api/auth/login', async (req, res) => {
    const { email, password } = req.body;
    const user = users.get(email);
    
    if (!user || !await bcrypt.compare(password, user.password)) {
        return res.status(401).json({ error: 'Credenciais inválidas' });
    }
    
    const token = jwt.sign({ id: user.id, email, name: user.name, isAdmin: user.isAdmin }, JWT_SECRET, { expiresIn: '24h' });
    res.json({ token, user: { id: user.id, email, name: user.name, isAdmin: user.isAdmin } });
});

app.get('/api/quiz/themes', (req, res) => {
    res.json(themes);
});

app.get('/api/quiz/themes/:id/questions', (req, res) => {
    const limit = parseInt(req.query.limit) || 10;
    res.json(questions.slice(0, limit));
});

app.post('/api/quiz/submit', auth, (req, res) => {
    const { themeId, answers, score, totalQuestions } = req.body;
    const result = {
        id: Date.now(),
        user_id: req.user.id,
        theme_id: themeId,
        score,
        total_questions: totalQuestions,
        completed_at: new Date()
    };
    
    if (!results.has(req.user.id)) results.set(req.user.id, []);
    results.get(req.user.id).push(result);
    
    res.json({ success: true, resultId: result.id, score, percentage: Math.round((score/totalQuestions)*100) });
});

app.get('/api/quiz/results', auth, (req, res) => {
    const userResults = results.get(req.user.id) || [];
    const formatted = userResults.map(r => ({
        id: r.id,
        score: r.score,
        total_questions: r.total_questions,
        completed_at: r.completed_at,
        theme_name: themes.find(t => t.id == r.theme_id)?.title || 'Tema',
        percentage: Math.round((r.score/r.total_questions)*100)
    }));
    res.json(formatted);
});

app.listen(PORT, () => {
    console.log(`🚀 Server rodando em http://localhost:${PORT}`);
    console.log(`📊 ${themes.length} temas disponíveis`);
    console.log('✅ Pronto para usar!');
});
