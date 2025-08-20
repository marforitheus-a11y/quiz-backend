// ==================================================================
// ARQUIVO server.js (VERSÃO FINAL COMPLETA - 20/08/2025)
// ==================================================================

// Carrega as variáveis de ambiente do arquivo .env APENAS em desenvolvimento local
if (process.env.NODE_ENV !== 'production') {
    require('dotenv').config();
}

// --- 1. IMPORTAÇÕES DE MÓDULOS ---
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const db = require('./db');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const pdfParse = require('pdf-parse');
const { GoogleGenerativeAI } = require("@google/generative-ai");

// --- 2. INICIALIZAÇÃO DE VARIÁVEIS E CLIENTES ---
const JWT_SECRET = process.env.JWT_SECRET;
const GEMINI_API_KEY = process.env.GEMINI_API_KEY;
const genAI = new GoogleGenerativeAI(GEMINI_API_KEY);

// --- 3. CONFIGURAÇÃO DO MULTER (UPLOAD DE ARQUIVOS) ---
const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        const dir = './uploads';
        if (!fs.existsSync(dir)){
            fs.mkdirSync(dir);
        }
        cb(null, dir);
    },
    filename: function (req, file, cb) {
        cb(null, Date.now() + '-' + file.originalname);
    }
});
const fileFilter = (req, file, cb) => {
    if (file.mimetype === 'application/pdf') {
        cb(null, true);
    } else {
        cb(new Error('Apenas PDFs são permitidos.'), false);
    }
};
const upload = multer({ storage: storage, fileFilter: fileFilter });

// --- 4. INICIALIZAÇÃO DO APP EXPRESS ---
const app = express();
const PORT = process.env.PORT || 3000;

// --- 5. CONFIGURAÇÃO DOS MIDDLEWARES GLOBAIS (A ORDEM IMPORTA!) ---
const corsOptions = {
    origin: 'https://quiz-frontend-nu-wheat.vercel.app', // SUA URL DO VERCEL
    methods: "GET,POST,PUT,DELETE,PATCH,OPTIONS",
    optionsSuccessStatus: 200
};
app.use(cors(corsOptions));
app.use(express.json());

// --- 6. FUNÇÕES AUXILIARES (MIDDLEWARES E IA) ---
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (token == null) return res.sendStatus(401);

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.sendStatus(403);
        req.user = user;
        next();
    });
}

function authorizeAdmin(req, res, next) {
    if (req.user.role !== 'admin') {
        return res.status(403).json({ message: "Acesso negado. Rota exclusiva para administradores." });
    }
    next();
}

async function generateQuestionsFromText(text) {
    try {
        console.log("IA: Chamando a API do Gemini para gerar questões...");
        const model = genAI.getGenerativeModel({ model: "gemini-pro" });
        const prompt = `Baseado no texto a seguir, gere 5 questões de concurso de múltipla escolha com 5 alternativas cada (A, B, C, D, E), com apenas uma correta. Responda APENAS com um JSON array válido no formato: [{"question": "...", "options": ["...", "..."], "answer": "..."}]. Texto: ${text.substring(0, 8000)}`;
        const result = await model.generateContent(prompt);
        const responseText = result.response.text();
        return JSON.parse(responseText);
    } catch (error) {
        console.error("Erro ao chamar a API do Gemini:", error);
        return null;
    }
}

// --- 7. DEFINIÇÃO DAS ROTAS DA API ---

// Rota pública para login
app.post('/login', async (req, res) => {
    const { username, password } = req.body;
    try {
        const result = await db.query('SELECT * FROM users WHERE username = $1', [username]);
        const user = result.rows[0];
        if (!user) return res.status(401).json({ message: "Usuário ou senha inválidos." });

        if (user.subscription_expires_at && new Date(user.subscription_expires_at) < new Date()) {
            console.log(`AVISO: O usuário '${user.username}' tentou logar com uma assinatura expirada.`);
            return res.status(403).json({ message: "Sua assinatura expirou." });
        }
        
        const isPasswordCorrect = await bcrypt.compare(password, user.password);
        if (isPasswordCorrect) {
            const payload = { id: user.id, username: user.username, role: user.role };
            const token = jwt.sign(payload, JWT_SECRET, { expiresIn: '8h' });
            res.status(200).json({ message: "Login bem-sucedido!", token: token });
        } else {
            res.status(401).json({ message: "Usuário ou senha inválidos." });
        }
    } catch (err) {
        console.error("Erro no login:", err);
        res.status(500).json({ message: 'Erro interno no servidor.' });
    }
});

// Rotas protegidas para usuários logados
app.get('/themes', authenticateToken, async (req, res) => {
    try {
        const result = await db.query('SELECT * FROM themes ORDER BY name');
        res.status(200).json(result.rows);
    } catch (err) {
        res.status(500).json({ message: 'Erro ao buscar temas.' });
    }
});

app.post('/questions', authenticateToken, async (req, res) => {
    const { themeIds, count } = req.body;
    try {
        const result = await db.query(
            'SELECT id, question, options, answer FROM questions WHERE theme_id = ANY($1::int[]) ORDER BY RANDOM() LIMIT $2',
            [themeIds, count]
        );
        res.status(200).json(result.rows);
    } catch (err) {
        res.status(500).json({ message: 'Erro ao buscar questões.' });
    }
});

app.post('/quiz/finish', authenticateToken, async (req, res) => {
    const { score, totalQuestions, answers } = req.body;
    const userId = req.user.id;
    try {
        const percentage = ((score / totalQuestions) * 100).toFixed(2);
        const historyResult = await db.query(
            'INSERT INTO quiz_history (user_id, score, total_questions, percentage) VALUES ($1, $2, $3, $4) RETURNING id',
            [userId, score, totalQuestions, percentage]
        );
        const newHistoryId = historyResult.rows[0].id;
        for (const answer of answers) {
            await db.query(
                'INSERT INTO user_answers (history_id, question_id, selected_option, is_correct) VALUES ($1, $2, $3, $4)',
                [newHistoryId, answer.questionId, answer.selectedOption, answer.isCorrect]
            );
        }
        res.status(201).json({ message: "Histórico salvo com sucesso!", historyId: newHistoryId });
    } catch (err) {
        res.status(500).json({ message: 'Erro ao salvar histórico.' });
    }
});

app.get('/history', authenticateToken, async (req, res) => {
    const userId = req.user.id;
    try {
        const result = await db.query(
            'SELECT id, score, total_questions, percentage, created_at FROM quiz_history WHERE user_id = $1 ORDER BY created_at DESC',
            [userId]
        );
        res.status(200).json(result.rows);
    } catch (err) {
        res.status(500).json({ message: 'Erro ao buscar histórico.' });
    }
});

app.get('/history/:id', authenticateToken, async (req, res) => {
    const { id } = req.params;
    const userId = req.user.id;
    try {
        const result = await db.query(`
            SELECT ua.question_id, q.question, q.options, q.answer as correct_answer, ua.selected_option, ua.is_correct
            FROM user_answers ua
            JOIN questions q ON ua.question_id = q.id
            JOIN quiz_history qh ON ua.history_id = qh.id
            WHERE ua.history_id = $1 AND qh.user_id = $2
        `, [id, userId]);
        if (result.rows.length === 0) return res.status(404).json({ message: "Histórico não encontrado." });
        res.status(200).json(result.rows);
    } catch (err) {
        res.status(500).json({ message: 'Erro ao buscar detalhes do histórico.' });
    }
});

app.post('/report-error', authenticateToken, async (req, res) => {
    // ... (cole aqui sua função de report-error completa e correta)
});

// Rotas protegidas para administradores
app.get('/admin/users', authenticateToken, authorizeAdmin, async (req, res) => {
    try {
        const result = await db.query('SELECT id, username, role, subscription_expires_at FROM users ORDER BY id ASC');
        res.status(200).json(result.rows);
    } catch (err) {
        res.status(500).json({ message: 'Erro ao buscar usuários.' });
    }
});

app.post('/admin/users', authenticateToken, authorizeAdmin, async (req, res) => {
    const { username, password, role, subscription_expires_at } = req.body;
    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        const result = await db.query(
            'INSERT INTO users (username, password, role, subscription_expires_at) VALUES ($1, $2, $3, $4) RETURNING id, username, role, subscription_expires_at',
            [username, hashedPassword, role || 'user', subscription_expires_at || null]
        );
        res.status(201).json({ message: "Usuário criado com sucesso!", user: result.rows[0] });
    } catch (err) {
        res.status(500).json({ message: 'Erro ao criar usuário.' });
    }
});

app.delete('/admin/users/:id', authenticateToken, authorizeAdmin, async (req, res) => {
    // ... (cole aqui sua função de delete users completa e correta)
});

app.get('/admin/reports', authenticateToken, authorizeAdmin, async (req, res) => {
    // ... (cole aqui sua função de get reports completa e correta)
});

app.post('/admin/themes', authenticateToken, authorizeAdmin, upload.single('pdfFile'), async (req, res) => {
    // ... (cole aqui sua função de post themes completa e correta)
});


// --- 8. INICIAR O SERVIDOR ---
app.listen(PORT, () => {
  console.log(`Servidor rodando e ouvindo na porta ${PORT}`);
});