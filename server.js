// ==================================================================
// ARQUIVO server.js (VERSÃO FINAL E COMPLETA)
// ==================================================================

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
    destination: (req, file, cb) => {
        const dir = './uploads';
        if (!fs.existsSync(dir)) { fs.mkdirSync(dir); }
        cb(null, dir);
    },
    filename: (req, file, cb) => cb(null, Date.now() + '-' + file.originalname)
});
const upload = multer({ storage: storage, fileFilter: (req, file, cb) => file.mimetype === 'application/pdf' ? cb(null, true) : cb(new Error('Apenas PDFs são permitidos.'), false) });

// --- 4. VARIÁVEIS GLOBAIS EM MEMÓRIA ---
let activeSessions = {};
let globalMessage = null;

// --- 5. INICIALIZAÇÃO DO APP EXPRESS ---
const app = express();
const PORT = process.env.PORT || 3000;

// --- 6. CONFIGURAÇÃO DOS MIDDLEWARES GLOBAIS ---
const corsOptions = {
    origin: 'https://quiz-frontend-nu-wheat.vercel.app', // ⚠️ SUBSTITUA PELA SUA URL CORRETA DO VERCEL SE FOR DIFERENTE
    methods: "GET,POST,PUT,DELETE,PATCH,OPTIONS",
    optionsSuccessStatus: 200
};
app.use(cors(corsOptions));
app.use(express.json());

// --- 7. FUNÇÕES AUXILIARES (MIDDLEWARES E IA) ---
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

async function generateQuestionsFromText(text, count) {
    try {
        console.log(`IA: Chamando API para gerar ${count} questões...`);
        const model = genAI.getGenerativeModel({ model: "gemini-1.5-flash-latest" });
        const prompt = `Baseado no texto a seguir, gere ${count} questões de concurso de múltipla escolha com 5 alternativas cada (A, B, C, D, E), com apenas uma correta. Responda APENAS com um JSON array válido no formato: [{"question": "...", "options": ["...", "..."], "answer": "..."}]. Texto: ${text.substring(0, 1000000)}`;
        const result = await model.generateContent(prompt);
        const responseText = result.response.text();
        const jsonMatch = responseText.match(/(\[[\s\S]*\])/);
        if (jsonMatch && jsonMatch[0]) {
            return JSON.parse(jsonMatch[0]);
        }
        throw new Error("Não foi possível encontrar um JSON válido na resposta da IA.");
    } catch (error) {
        console.error("Erro na geração de questões pela IA:", error);
        throw new Error("A IA não conseguiu gerar as questões.");
    }
}

// --- 8. ROTAS DA API ---

// ROTA DE LOGIN E LOGOUT
app.post('/login', async (req, res) => {
    const { username, password } = req.body;
    try {
        const result = await db.query('SELECT * FROM users WHERE username = $1', [username]);
        const user = result.rows[0];
        if (!user) return res.status(401).json({ message: "Usuário ou senha inválidos." });

        if (user.subscription_expires_at && new Date(user.subscription_expires_at) < new Date()) {
            return res.status(403).json({ message: "Sua assinatura expirou." });
        }
        
        const isPasswordCorrect = await bcrypt.compare(password, user.password);
        if (isPasswordCorrect) {
            const payload = { id: user.id, username: user.username, role: user.role };
            const token = jwt.sign(payload, JWT_SECRET, { expiresIn: '8h' });
            activeSessions[user.username] = { role: user.role, loginTime: new Date() };
            res.status(200).json({ message: "Login bem-sucedido!", token: token });
        } else {
            res.status(401).json({ message: "Usuário ou senha inválidos." });
        }
    } catch (err) {
        console.error("Erro no login:", err);
        res.status(500).json({ message: 'Erro interno no servidor.' });
    }
});

app.post('/logout', (req, res) => {
    const { username } = req.body;
    if (username && activeSessions[username]) {
        delete activeSessions[username];
        console.log(`Sessão do usuário ${username} encerrada.`);
    }
    res.status(200).json({ message: "Logout bem-sucedido."});
});

// ROTAS DE USUÁRIO
app.get('/message', authenticateToken, (req, res) => {
    if (globalMessage) {
        return res.status(200).json(globalMessage);
    } else {
        return res.status(204).send();
    }
});

app.get('/themes', authenticateToken, async (req, res) => {
    try {
        const result = await db.query('SELECT * FROM themes ORDER BY id ASC');
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
        const percentage = totalQuestions > 0 ? ((score / totalQuestions) * 100).toFixed(2) : 0;
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
    const { questionId, errorType, details } = req.body;
    const userId = req.user.id;
    try {
        await db.query(
            'INSERT INTO reported_errors (question_id, user_id, error_type, details) VALUES ($1, $2, $3, $4)',
            [questionId, userId, errorType, details]
        );
        res.status(200).json({ message: "Erro reportado com sucesso. Agradecemos sua colaboração." });
    } catch (err) {
        res.status(500).json({ message: 'Erro ao registrar o reporte.' });
    }
});

// ROTAS DE ADMIN
app.post('/admin/broadcast', authenticateToken, authorizeAdmin, (req, res) => {
    const { message } = req.body;
    if (!message) {
        return res.status(400).json({ message: "O conteúdo da mensagem é obrigatório." });
    }
    globalMessage = { content: message, timestamp: new Date() };
    setTimeout(() => { globalMessage = null; }, 60000);
    res.status(200).json({ message: "Mensagem global enviada com sucesso e ficará ativa por 1 minuto." });
});

app.get('/admin/sessions', authenticateToken, authorizeAdmin, (req, res) => {
    res.status(200).json(activeSessions);
});

app.get('/admin/users', authenticateToken, authorizeAdmin, async (req, res) => {
    try {
        const result = await db.query('SELECT id, username, role, subscription_expires_at FROM users ORDER BY id ASC');
        const users = result.rows.map(user => ({
            ...user,
            isActive: !!activeSessions[user.username]
        }));
        res.status(200).json(users);
    } catch (err) {
        res.status(500).json({ message: 'Erro ao buscar usuários.' });
    }
});

app.post('/admin/users', authenticateToken, authorizeAdmin, async (req, res) => {
    const { username, password, role, subscription_expires_at } = req.body;
    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        const result = await db.query(
            'INSERT INTO users (username, password, role, subscription_expires_at) VALUES ($1, $2, $3, $4) RETURNING id, username, role',
            [username, hashedPassword, role || 'user', subscription_expires_at || null]
        );
        res.status(201).json({ message: "Usuário criado com sucesso!", user: result.rows[0] });
    } catch (err) {
        res.status(500).json({ message: 'Erro ao criar usuário. O nome de usuário já pode existir.' });
    }
});

app.delete('/admin/users/:id', authenticateToken, authorizeAdmin, async (req, res) => {
    const userIdToDelete = parseInt(req.params.id, 10);
    const adminUserId = req.user.id;
    if (userIdToDelete === adminUserId) {
        return res.status(403).json({ message: "Um administrador não pode apagar a própria conta." });
    }
    try {
        const result = await db.query('DELETE FROM users WHERE id = $1 RETURNING id', [userIdToDelete]);
        if (result.rowCount === 0) return res.status(404).json({ message: "Usuário não encontrado." });
        res.status(200).json({ message: `Usuário com ID ${userIdToDelete} foi apagado.` });
    } catch (err) {
        res.status(500).json({ message: 'Erro ao apagar usuário.' });
    }
});

app.get('/admin/reports', authenticateToken, authorizeAdmin, async (req, res) => {
    try {
        const result = await db.query(`
            SELECT r.id, r.status, r.error_type, q.question, u.username as reported_by, r.reported_at 
            FROM reported_errors r
            JOIN questions q ON r.question_id = q.id
            JOIN users u ON r.user_id = u.id
            ORDER BY r.reported_at DESC LIMIT 20
        `);
        res.status(200).json(result.rows);
    } catch (err) {
        res.status(500).json({ message: 'Erro ao buscar reportes.' });
    }
});

app.post('/admin/themes', authenticateToken, authorizeAdmin, upload.single('pdfFile'), async (req, res) => {
    const { themeName, questionCount } = req.body;
    const file = req.file;
    if (!file || !themeName || !questionCount) {
        return res.status(400).json({ message: "Nome do tema, arquivo PDF e quantidade de questões são obrigatórios." });
    }
    try {
        const dataBuffer = fs.readFileSync(file.path);
        const data = await pdfParse(dataBuffer);
        const generatedQuestions = await generateQuestionsFromText(data.text, questionCount);
        const themeResult = await db.query('INSERT INTO themes (name) VALUES ($1) RETURNING id', [themeName]);
        const newThemeId = themeResult.rows[0].id;
        for (const q of generatedQuestions) {
            await db.query(
                'INSERT INTO questions (theme_id, question, options, answer) VALUES ($1, $2, $3, $4)',
                [newThemeId, q.question, q.options, q.answer]
            );
        }
        res.status(201).json({ message: `Tema '${themeName}' e ${generatedQuestions.length} questões foram adicionadas.` });
    } catch (err) {
        console.error("Erro no upload de tema:", err);
        res.status(500).json({ message: 'Erro no servidor ao processar o arquivo.', error: err.message });
    } finally {
        if (file && file.path) {
            fs.unlinkSync(file.path);
        }
    }
});

// SUBSTITUA A ROTA DE DELETAR TEMA PELA VERSÃO ABAIXO em server.js

app.delete('/admin/themes/:id', authenticateToken, authorizeAdmin, async (req, res) => {
    const { id } = req.params;
    try {
        // Passo 1: Encontrar todas as IDs das questões associadas ao tema que será apagado.
        const questionsResult = await db.query('SELECT id FROM questions WHERE theme_id = $1', [id]);
        const questionIds = questionsResult.rows.map(q => q.id);

        // Passo 2: Se existirem questões, apagar todas as entradas na tabela 'user_answers'
        // que fazem referência a essas questões.
        if (questionIds.length > 0) {
            await db.query('DELETE FROM user_answers WHERE question_id = ANY($1::int[])', [questionIds]);
        }

        // Passo 3: Agora que as dependências foram removidas, apagar o tema.
        // Graças ao "ON DELETE CASCADE" que definimos, ao apagar o tema, o PostgreSQL
        // automaticamente apagará todas as questões associadas a ele.
        const result = await db.query('DELETE FROM themes WHERE id = $1 RETURNING name', [id]);

        if (result.rowCount === 0) {
            return res.status(404).json({ message: "Tema não encontrado." });
        }

        res.status(200).json({ message: `Tema '${result.rows[0].name}' e todo o seu histórico foram apagados com sucesso.` });
        
    } catch (err) {
        console.error("Erro ao apagar tema e suas dependências:", err);
        res.status(500).json({ message: 'Erro no servidor ao apagar o tema.' });
    }
});

app.post('/admin/themes/:id/reset', authenticateToken, authorizeAdmin, upload.single('pdfFile'), async (req, res) => {
    const { id } = req.params;
    const { questionCount } = req.body;
    const file = req.file;
    if (!file || !questionCount) {
        return res.status(400).json({ message: "Arquivo PDF e quantidade de questões são obrigatórios." });
    }
    try {
        await db.query('DELETE FROM questions WHERE theme_id = $1', [id]);
        const dataBuffer = fs.readFileSync(file.path);
        const data = await pdfParse(dataBuffer);
        const newQuestions = await generateQuestionsFromText(data.text, questionCount);
        for (const q of newQuestions) {
            await db.query(
                'INSERT INTO questions (theme_id, question, options, answer) VALUES ($1, $2, $3, $4)',
                [id, q.question, q.options, q.answer]
            );
        }
        res.status(200).json({ message: `Tema resetado com ${newQuestions.length} novas questões.` });
    } catch (err) {
        res.status(500).json({ message: 'Erro ao resetar tema.', error: err.message });
    } finally {
        if (file && file.path) { fs.unlinkSync(file.path); }
    }
});

// --- INICIAR O SERVIDOR ---
app.listen(PORT, () => {
  console.log(`Servidor rodando e ouvindo na porta ${PORT}`);
});