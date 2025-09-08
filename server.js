// ==================================================================
// ARQUIVO server.js (VERSÃO FINAL COMPLETA)
// ==================================================================

if (process.env.NODE_ENV !== 'production') {
    require('dotenv').config();
}

// --- 1. IMPORTAÇÕES DE MÓDULOS ---
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const db = require('./db');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const pdfParse = require('pdf-parse');
const { GoogleGenerativeAI } = require("@google/generative-ai");
const axios = require('axios');
const FormData = require('form-data');
const session = require('express-session');
const passport = require('passport');
const authRoutes = require('./app/auth_routes.js');

// --- 2. INICIALIZAÇÃO DE VARIÁVEIS E CLIENTES ---
const JWT_SECRET = process.env.JWT_SECRET;
const GEMINI_API_KEY = process.env.GEMINI_API_KEY;
const IMGBB_API_KEY = process.env.IMGBB_API_KEY;
const genAI = new GoogleGenerativeAI(GEMINI_API_KEY);

// Critical env checks
if (!JWT_SECRET) {
    console.error('FATAL: JWT_SECRET is not set. Set it in environment variables.');
    process.exit(1);
}

// --- 3. CONFIGURAÇÃO DO MULTER (UPLOAD DE ARQUIVOS) ---
const { v4: uuidv4 } = require('uuid');

// Secure multer setup: use safe filenames, limit size and filter mime types
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        const dir = './uploads';
        if (!fs.existsSync(dir)) { fs.mkdirSync(dir, { recursive: true }); }
        cb(null, dir);
    },
    filename: (req, file, cb) => {
        // keep only extension from original filename
        const ext = path.extname(file.originalname).toLowerCase();
        const safeName = `${Date.now()}-${uuidv4()}${ext}`;
        cb(null, safeName);
    }
});

function fileFilter(req, file, cb) {
    const allowed = ['.pdf', '.png', '.jpg', '.jpeg', '.gif'];
    const ext = path.extname(file.originalname).toLowerCase();
    if (!allowed.includes(ext)) {
        return cb(new Error('Tipo de arquivo não permitido'), false);
    }
    // basic mime-type check
    if (!file.mimetype) return cb(new Error('Mime type missing'), false);
    cb(null, true);
}

const upload = multer({ storage: storage, fileFilter, limits: { fileSize: 10 * 1024 * 1024 } }); // 10MB

// --- 4. VARIÁVEIS GLOBAIS EM MEMÓRIA ---
let activeSessions = {};
let globalMessage = null;

// --- 5. INICIALIZAÇÃO DO APP EXPRESS ---
const app = express();
const PORT = process.env.PORT || 3000;

// --- 6. CONFIGURAÇÃO DOS MIDDLEWARES GLOBAIS ---
// CORS: allow configured frontend origins (comma-separated) and common hosting domains like vercel.app
const FRONTEND_URL = process.env.FRONTEND_URL || 'http://localhost:5500';
const FRONTEND_URLS = FRONTEND_URL.split(',').map(s => s.trim()).filter(Boolean);
const corsOptions = {
    origin: function (origin, callback) {
        // allow requests with no origin (like curl, server-to-server)
        if (!origin) return callback(null, true);
        // allow explicit configured origins
        if (FRONTEND_URLS.includes(origin)) return callback(null, true);
        // allow preview/staging domains commonly used (conservative rule)
        if (origin.includes('vercel.app') || origin.includes('netlify.app')) return callback(null, true);
        return callback(new Error('CORS policy: This origin is not allowed'), false);
    },
    methods: "GET,POST,PUT,DELETE,PATCH,OPTIONS",
    optionsSuccessStatus: 200
};
app.use(cors(corsOptions));

// Security headers
app.use(helmet());

// TEMPORARY: log incoming requests (method, path, origin) to help debug routing issues like "Cannot POST /..."
// Remove or reduce verbosity after debugging.
app.use((req, res, next) => {
    try {
        const origin = req.headers.origin || req.headers.referer || '';
        console.log(`[REQ] ${new Date().toISOString()} ${req.method} ${req.originalUrl} Host:${req.get('host')} Origin:${origin}`);
        
        // Log especial para rotas de auth
        if (req.originalUrl.startsWith('/auth')) {
            console.log(`[AUTH-REQ] Auth route detected: ${req.method} ${req.originalUrl}`);
            console.log(`[AUTH-REQ] Headers:`, JSON.stringify(req.headers, null, 2));
        }
    } catch (e) {
        console.error('[REQ-LOG-ERROR]', e);
    }
    next();
});

// Basic CSP additional header (can be refined for your assets)
app.use((req, res, next) => {
    res.setHeader("Content-Security-Policy", "default-src 'self'; img-src 'self' data: https:; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline';");
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('Referrer-Policy', 'no-referrer');
    next();
});

// Rate limiting
const globalLimiter = rateLimit({ windowMs: 60 * 1000, max: 200 }); // 200 requests per minute per IP
app.use(globalLimiter);
const aiLimiter = rateLimit({ windowMs: 60 * 1000, max: 10 }); // stricter for AI endpoints
app.use(express.json());

// --- 6.1. CONFIGURAÇÃO DE SESSÃO E AUTENTICAÇÃO (PASSPORT) ---
app.use(session({
    secret: process.env.SESSION_SECRET || 'a_fallback_secret_for_session', // Fallback for local dev
    resave: false,
    saveUninitialized: false,
    cookie: {
        secure: process.env.NODE_ENV === 'production', // Use secure cookies in production
        httpOnly: true,
        maxAge: 24 * 60 * 60 * 1000 // 24 hours
    }
}));

app.use(passport.initialize());
app.use(passport.session());

// Configurar estratégias do Passport
try {
    require('./app/auth_config.js')(passport);
    console.log('[PASSPORT] Estratégias do Passport configuradas com sucesso');
} catch (error) {
    console.error('[PASSPORT-ERROR] Erro ao configurar estratégias do Passport:', error);
    console.error('[PASSPORT-ERROR] Stack:', error.stack);
}

// --- 6.2. ROTAS DE AUTENTICAÇÃO SOCIAL ---
// Debug endpoint para verificar configurações OAuth
app.get('/auth/debug', (req, res) => {
    try {
        const config = {
            google_client_id: process.env.GOOGLE_CLIENT_ID ? 'Configurado' : 'NÃO CONFIGURADO',
            google_client_secret: process.env.GOOGLE_CLIENT_SECRET ? 'Configurado' : 'NÃO CONFIGURADO',
            facebook_app_id: process.env.FACEBOOK_APP_ID ? 'Configurado' : 'NÃO CONFIGURADO',
            facebook_app_secret: process.env.FACEBOOK_APP_SECRET ? 'Configurado' : 'NÃO CONFIGURADO',
            session_secret: process.env.SESSION_SECRET ? 'Configurado' : 'NÃO CONFIGURADO',
            node_env: process.env.NODE_ENV || 'NÃO CONFIGURADO',
            timestamp: new Date().toISOString()
        };
        console.log('Debug OAuth config:', config);
        res.json(config);
    } catch (error) {
        console.error('Erro no debug endpoint:', error);
        res.status(500).json({ error: 'Erro interno', message: error.message });
    }
});

// Rota de teste para debug
app.get('/auth/test', (req, res) => {
    res.json({ message: 'Auth routes are working!', timestamp: new Date().toISOString() });
});

app.use('/auth', authRoutes);

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
    // default easy prompt
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

// Variantes de prompt por dificuldade
function buildPromptForDifficulty(baseText, count, difficulty) {
    const easy = `Gere ${count} questões de múltipla escolha fáceis (apenas uma correta). Use linguagem clara e enunciados diretos.`;
    const medium = `Gere ${count} questões de dificuldade média. Itens devem incluir enunciados com contexto prático e alternativas que estejam próximas semanticamente da alternativa correta. Use formatos como:\nI. (Frase quase totalmente certa com item errado ao final)\nII. (Afirmação correta de acordo com o tema)\nIII. (Afirmação incorreta)\nVarie entre corretas e incorretas e inclua contextos do cotidiano que exijam interpretação.`;
    const hard = `Gere ${count} questões de alta dificuldade. Construa enunciados que mudem pequenas palavras para induzir ao erro; evite perguntas do tipo "O que contém no artigo X" ou que peçam informação externa não contida no enunciado. Prefira questões que peçam: "Selecione a alternativa que contém um item correto (ou incorreto) conforme a lei Y" e ofereça alternativas muito próximas entre si.`;
    const base = String(baseText).slice(0, 60000);
    let core = easy;
    if (difficulty === 'medium') core = medium;
    if (difficulty === 'hard') core = hard;
    return `${core}\nContexto/Texto para referência: ${base}\nResponda apenas com um JSON array válido no formato [{"question":"...","options":["...","...","...","...","..."],"answer":"..."}].`;
}

// Generate questions directly from a topic using the generative model (no web scraping)
async function generateQuestionsFromTopic(topic, count, difficulty = 'easy') {
    try {
        console.log(`IA: gerando ${count} questões diretamente a partir do tópico: ${topic}`);
        const model = genAI.getGenerativeModel({ model: "gemini-1.5-flash-latest" });
    const prompt = buildPromptForDifficulty(topic, count, difficulty);
        const result = await model.generateContent(prompt);
        const responseText = result.response.text();
        const jsonMatch = responseText.match(/(\[[\s\S]*\])/);
        if (jsonMatch && jsonMatch[0]) return JSON.parse(jsonMatch[0]);
        throw new Error('Não foi possível interpretar a resposta da IA como JSON válido.');
    } catch (err) {
        console.error('Erro generateQuestionsFromTopic:', err && err.message ? err.message : err);
        throw new Error('A IA não conseguiu gerar questões a partir do tópico.');
    }
}

async function generateTopicSummary(topic) {
    try {
    console.log('generateTopicSummary: asking generative model for topic summary:', topic);
    const model = genAI.getGenerativeModel({ model: "gemini-1.5-flash-latest" });
    const prompt = `For the topic: "${topic}", produce a clear, factual summary of up to 4000 characters suitable as source material for creating multiple choice questions. Use neutral tone and include key definitions, principles and examples where appropriate. Return only the plain text summary.`;
    const result = await model.generateContent(prompt);
    const text = result.response.text();
        // keep a reasonable cap
        return String(text).slice(0, 60000);
    } catch (err) {
        console.error('generateTopicSummary failed', err && err.message ? err.message : err);
        throw new Error('Falha ao gerar resumo do tópico via IA. Tente novamente mais tarde.');
    }
}

// Resolve answer text: if AI returned a letter (A-E) or 'A: text', convert to the actual option string
function resolveAnswerText(q) {
    try {
        if (!q) return '';
        const opts = Array.isArray(q.options) ? q.options : [];
        let ans = (q.answer === null || q.answer === undefined) ? '' : String(q.answer).trim();
        if (!ans) return '';

        // If answer is a single letter like 'A' or 'b', map to option index
        const letterMatch = ans.match(/^\s*([A-Ea-e])\s*[:.)-]?\s*(.*)$/);
        if (letterMatch) {
            const letter = letterMatch[1].toUpperCase();
            const remainder = letterMatch[2] || '';
            const idx = letter.charCodeAt(0) - 65; // A->0
            if (opts[idx]) return String(opts[idx]).trim();
            // if remainder contains the actual text, prefer it
            if (remainder && remainder.length > 0) return remainder.trim();
        }

        // If answer is numeric index like '1'..'5'
        const numMatch = ans.match(/^\s*([1-5])\s*$/);
        if (numMatch) {
            const idx = parseInt(numMatch[1], 10) - 1;
            if (opts[idx]) return String(opts[idx]).trim();
        }

        // If answer matches one of the options (case-insensitive), return the option
        for (const o of opts) {
            if (!o) continue;
            if (String(o).trim().toLowerCase() === ans.trim().toLowerCase()) return String(o).trim();
        }

        // If answer contains ':' and then text, take the part after ':'
        const colonMatch = ans.match(/^[A-Ea-e]\s*[:.)-]\s*(.*)$/);
        if (colonMatch && colonMatch[1]) return colonMatch[1].trim();

        // fallback: return original answer
        return ans;
    } catch (err) {
        console.warn('resolveAnswerText failed', err && err.message ? err.message : err);
        return q.answer || '';
    }
}

// If AI returned all options in a single string like "A) X B) Y C) Z", split into array
function splitOptionsFromString(s) {
    try {
        if (!s || typeof s !== 'string') return [String(s || '').trim()];
        // find markers like A) or A. or A: or A- (case-insensitive)
        const markerRegex = /([A-Ea-e])[\)\.:\-]\s*/g;
        const markers = [...s.matchAll(markerRegex)];
        if (markers.length >= 2) {
            const opts = [];
            for (let i = 0; i < markers.length; i++) {
                const start = markers[i].index + markers[i][0].length;
                const end = (i + 1 < markers.length) ? markers[i + 1].index : s.length;
                const piece = s.slice(start, end).trim();
                if (piece) opts.push(piece);
            }
            if (opts.length > 0) return opts;
        }
        // fallback splits
        const byNewline = s.split(/\r?\n/).map(x => x.trim()).filter(Boolean);
        if (byNewline.length > 1) return byNewline;
        const bySemicolon = s.split(/;+/).map(x => x.trim()).filter(Boolean);
        if (bySemicolon.length > 1) return bySemicolon;
        const byPipe = s.split('|').map(x => x.trim()).filter(Boolean);
        if (byPipe.length > 1) return byPipe;
        return [s.trim()];
    } catch (err) {
        return [String(s).trim()];
    }
}

function sanitizeQuestionRow(row) {
    // options normalization
    let opts = row.options;
    if (!opts) opts = [];
    if (typeof opts === 'string') {
        opts = splitOptionsFromString(opts);
    } else if (Array.isArray(opts) && opts.length === 1 && typeof opts[0] === 'string') {
        const maybe = splitOptionsFromString(opts[0]);
        if (maybe.length > 1) opts = maybe;
    }
    if (!Array.isArray(opts)) opts = [String(opts)];
    opts = opts.map(o => (o === null || o === undefined) ? '' : String(o).trim());

    // answer normalization: map letter to option text if needed
    let ans = (row.answer === null || row.answer === undefined) ? '' : String(row.answer).trim();
    // single letter like 'A'
    const letterOnly = ans.match(/^\s*([A-Ea-e])\s*$/);
    if (letterOnly) {
        const idx = letterOnly[1].toUpperCase().charCodeAt(0) - 65;
        if (opts[idx]) ans = opts[idx];
    }
    // patterns like 'A) text' -> extract text
    const afterMarker = ans.match(/^[A-Ea-e][\)\.:\-]\s*(.*)$/);
    if (afterMarker && afterMarker[1]) ans = afterMarker[1].trim();
    // if ans matches an option ignoring case, pick canonical option
    const matched = opts.find(o => o.trim().toLowerCase() === ans.trim().toLowerCase());
    if (matched) ans = matched;

    return { ...row, options: opts, answer: ans };
}

// --- 8. ROTAS DA API ---

// ROTA DE CADASTRO (NOVA)
app.post('/signup', async (req, res) => {
    const { name, email, username, password } = req.body;
    if (!name || !email || !username || !password) {
        return res.status(400).json({ message: "Nome, e-mail, usuário e senha são obrigatórios." });
    }
    try {
        const existingUser = await db.query('SELECT * FROM users WHERE username = $1 OR email = $2', [username, email]);
        if (existingUser.rows.length > 0) {
            return res.status(409).json({ message: "Nome de usuário ou e-mail já cadastrado." });
        }
        const hashedPassword = await bcrypt.hash(password, 10);
        const result = await db.query(
            'INSERT INTO users (name, email, username, password, role, is_pay, daily_quiz_count) VALUES ($1, $2, $3, $4, $5, $6, 0) RETURNING id, name, username, role',
            [name, email, username, hashedPassword, 'user', false]
        );
        res.status(201).json({ message: "Conta criada com sucesso!", user: result.rows[0] });
    } catch (err) {
        console.error("Erro no cadastro:", err);
        res.status(500).json({ message: 'Erro interno no servidor ao criar a conta.' });
    }
});

// ROTA DE LOGIN (ATUALIZADA)
app.post('/login', async (req, res) => {
    const { loginIdentifier, password } = req.body;
    try {
        const result = await db.query('SELECT * FROM users WHERE username = $1 OR email = $1', [loginIdentifier]);
        const user = result.rows[0];
        if (!user) return res.status(401).json({ message: "Usuário ou senha inválidos." });

        // Se o usuário não for pagante mas tiver uma data de expiração no passado, bloqueia.
        if (user.is_pay === false && user.subscription_expires_at && new Date(user.subscription_expires_at) < new Date()) {
            return res.status(403).json({ message: "Sua assinatura expirou. Renove para continuar." });
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
    }
    res.status(200).json({ message: "Logout bem-sucedido."});
});

// Lightweight health endpoint for uptime checks and external pings.
// Responds quickly and can be used by monitors (UptimeRobot, GitHub Actions) to keep the instance warm.
app.get('/health', async (req, res) => {
    try {
        // simple JSON payload with uptime and timestamp
        return res.status(200).json({ status: 'ok', uptime_seconds: Math.floor(process.uptime()), ts: new Date().toISOString() });
    } catch (err) {
        return res.status(500).json({ status: 'error' });
    }
});

// ROTA DE CONTA
app.get('/account/me', authenticateToken, async (req, res) => {
    try {
        const result = await db.query(
            'SELECT username, name, subscription_expires_at FROM users WHERE id = $1',
            [req.user.id]
        );
        res.status(200).json(result.rows[0]);
    } catch (err) {
        res.status(500).json({ message: 'Erro ao buscar dados da conta.' });
    }
});
app.put('/account/me', authenticateToken, async (req, res) => {
    const { name } = req.body;
    try {
        const result = await db.query(
            'UPDATE users SET name = $1 WHERE id = $2 RETURNING id, username, name',
            [name, req.user.id]
        );
        res.status(200).json(result.rows[0]);
    } catch (err) {
        res.status(500).json({ message: 'Erro ao atualizar o nome.' });
    }
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
        // Ensure categories table exists (safeguard for freshly created DBs)
        await db.query(`CREATE TABLE IF NOT EXISTS categories (
            id SERIAL PRIMARY KEY,
            name TEXT NOT NULL,
            parent_id INTEGER NULL
        )`);

        // Ensure themes table exists and expected columns are present
        await db.query(`CREATE TABLE IF NOT EXISTS themes (
            id SERIAL PRIMARY KEY,
            name TEXT NOT NULL
        )`);
        // Add optional columns if missing (safe idempotent migrations)
        await db.query(`ALTER TABLE themes ADD COLUMN IF NOT EXISTS description TEXT`);
        await db.query(`ALTER TABLE themes ADD COLUMN IF NOT EXISTS category_id INTEGER NULL`);

        // Return themes with optional category info
        async function runThemesQuery() {
            return await db.query(`
                SELECT t.id, t.name, t.description, t.category_id, c.name as category_name, c.parent_id as category_parent_id,
                       p.id as parent_cat_id, p.name as parent_cat_name,
                       (SELECT COUNT(q.id) FROM questions q WHERE q.theme_id = t.id) as question_count
                FROM themes t
                LEFT JOIN categories c ON t.category_id = c.id
                LEFT JOIN categories p ON c.parent_id = p.id
                ORDER BY t.id ASC
            `);
        }

        try {
            const result = await runThemesQuery();
            return res.status(200).json(result.rows);
        } catch (err) {
            // attempt to auto-fix common missing-column issues and retry once
            const msg = err && err.message ? err.message : String(err);
            const colMatch = msg.match(/column "?([a-zA-Z0-9_]+)"? does not exist/);
            if (colMatch) {
                const col = colMatch[1];
                console.warn('GET /themes detected missing column:', col, 'attempting safe migration');
                try {
                    if (col === 'description') {
                        await db.query('ALTER TABLE themes ADD COLUMN IF NOT EXISTS description TEXT');
                    } else if (col === 'category_id') {
                        await db.query('ALTER TABLE themes ADD COLUMN IF NOT EXISTS category_id INTEGER NULL');
                    } else if (col === 'name' || col === 'parent_id') {
                        // ensure categories table has expected columns
                        await db.query(`CREATE TABLE IF NOT EXISTS categories (
                            id SERIAL PRIMARY KEY,
                            name TEXT NOT NULL,
                            parent_id INTEGER NULL
                        )`);
                    } else {
                        // fallback: try to add column to themes as text (safe) if it seems theme-related
                        // avoid dangerous ops for unknown columns
                        if (col.startsWith('t_') || ['title','summary'].includes(col)) {
                            await db.query(`ALTER TABLE themes ADD COLUMN IF NOT EXISTS ${col} TEXT`);
                        }
                    }
                    // retry once
                    const retry = await runThemesQuery();
                    return res.status(200).json(retry.rows);
                } catch (fixErr) {
                    console.error('Auto-fix for GET /themes failed:', fixErr && fixErr.message ? fixErr.message : fixErr);
                    return res.status(500).json({ message: 'Erro ao buscar temas.', error: msg, repairError: fixErr && fixErr.message ? fixErr.message : String(fixErr) });
                }
            }
            // not a known missing-column error, bubble up
            throw err;
        }
    } catch (err) {
        console.error('GET /themes error:', err && err.message ? err.message : err);
        // return error message to client for debugging (will be visible in admin debug panel)
        res.status(500).json({ message: 'Erro ao buscar temas.', error: err && err.message ? err.message : String(err) });
    }
});

app.post('/questions', authenticateToken, async (req, res) => {
    const { themeIds, count, difficulties } = req.body;
    const userId = req.user.id;

    try {
        // Verificar status de pagamento e limite diário
        const userResult = await db.query('SELECT is_pay, last_quiz_date, daily_quiz_count FROM users WHERE id = $1', [userId]);
        const user = userResult.rows[0];

        if (!user.is_pay) {
            const today = new Date().toISOString().split('T')[0];
            const lastQuizDate = user.last_quiz_date ? new Date(user.last_quiz_date).toISOString().split('T')[0] : null;

            let dailyCount = user.daily_quiz_count;

            if (today !== lastQuizDate) {
                // Resetar a contagem se for um novo dia
                dailyCount = 0;
                await db.query('UPDATE users SET daily_quiz_count = 0, last_quiz_date = $1 WHERE id = $2', [today, userId]);
            }

            if (dailyCount >= 10) {
                return res.status(403).json({ message: "Você atingiu o limite de 10 questões por dia. Torne-se um usuário VIP para acesso ilimitado." });
            }
        }

        // Lógica para buscar questões
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

        // Atualizar contagem diária para usuários não-pagantes
        if (!user.is_pay) {
            const newCount = (user.daily_quiz_count || 0) + sanitized.length;
            await db.query('UPDATE users SET daily_quiz_count = $1 WHERE id = $2', [newCount, userId]);
        }

        res.status(200).json(sanitized);
    } catch (err) {
        console.error("Erro ao buscar questões:", err);
        res.status(500).json({ message: 'Erro ao buscar questões.' });
    }
});

// return counts of available questions grouped by difficulty for given theme ids
// Helper to normalize themeIds from POST body or GET query
function parseThemeIdsFromRequest(req) {
    try {
        // Prefer JSON body for POST
        if (req.method === 'POST') {
            const { themeIds, themeId } = req.body || {};
            if (Array.isArray(themeIds) && themeIds.length > 0) return themeIds.map(n => parseInt(n, 10)).filter(n => !isNaN(n));
            if (themeId !== undefined) {
                const v = Array.isArray(themeId) ? themeId : String(themeId).split(',');
                return v.map(n => parseInt(n, 10)).filter(n => !isNaN(n));
            }
        }
        // Also accept GET: ?themeIds=1,2,3 or repeated ?themeId=1&themeId=2
        const q = req.query || {};
        if (q.themeIds) {
            const list = String(q.themeIds).split(',');
            return list.map(n => parseInt(n, 10)).filter(n => !isNaN(n));
        }
        if (q.themeId) {
            const list = Array.isArray(q.themeId) ? q.themeId : String(q.themeId).split(',');
            return list.map(n => parseInt(n, 10)).filter(n => !isNaN(n));
        }
        return [];
    } catch (_) { return []; }
}

async function handleCountRequest(req, res) {
    const ids = parseThemeIdsFromRequest(req);
    if (!ids || ids.length === 0) return res.status(400).json({ message: 'themeIds obrigatório.' });
    try {
        const q = await db.query(
            `SELECT COALESCE(difficulty, 'easy') AS difficulty, COUNT(*) AS cnt
             FROM questions WHERE theme_id = ANY($1::int[]) GROUP BY difficulty`,
            [ids]
        );
        const out = { easy: 0, medium: 0, hard: 0 };
        for (const row of q.rows) {
            const d = row.difficulty || 'easy';
            out[d] = parseInt(row.cnt, 10);
        }
        return res.status(200).json(out);
    } catch (err) {
        console.error('questions/counts failed', err);
        return res.status(500).json({ message: 'Erro ao contar questões.' });
    }
}

// Primary route (POST)
app.post('/questions/counts', authenticateToken, handleCountRequest);
// Compatibility aliases to avoid 404s on older frontend/deploys
app.get('/questions/counts', authenticateToken, handleCountRequest);
app.post('/questions/count', authenticateToken, handleCountRequest);
app.get('/questions/count', authenticateToken, handleCountRequest);

// Return counts grouped by theme and difficulty for the provided theme IDs
async function handleCountsByTheme(req, res) {
    const ids = parseThemeIdsFromRequest(req);
    if (!ids || ids.length === 0) return res.status(400).json({ message: 'themeIds obrigatório.' });
    try {
        const q = await db.query(
            `SELECT theme_id, COALESCE(difficulty, 'easy') AS difficulty, COUNT(*) AS cnt
             FROM questions WHERE theme_id = ANY($1::int[]) GROUP BY theme_id, difficulty` ,
            [ids]
        );
        const out = {};
        for (const row of q.rows) {
            const tid = row.theme_id;
            if (!out[tid]) out[tid] = { easy: 0, medium: 0, hard: 0 };
            const d = row.difficulty || 'easy';
            out[tid][d] = parseInt(row.cnt, 10);
        }
        return res.status(200).json(out);
    } catch (err) {
        console.error('questions/counts-by-theme failed', err);
        return res.status(500).json({ message: 'Erro ao contar questões por tema.' });
    }
}

app.post('/questions/counts-by-theme', authenticateToken, handleCountsByTheme);
app.get('/questions/counts-by-theme', authenticateToken, handleCountsByTheme);

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
            SELECT ua.question_id, q.theme_id, q.question, q.options, q.answer as correct_answer, ua.selected_option, ua.is_correct
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
        // Create reports table if it doesn't exist
        await db.query(`
            CREATE TABLE IF NOT EXISTS reports (
                id SERIAL PRIMARY KEY,
                question_id INTEGER REFERENCES questions(id) ON DELETE CASCADE,
                user_id INTEGER,
                reason TEXT,
                description TEXT,
                status TEXT DEFAULT 'pending',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `);
        
        await db.query(
            'INSERT INTO reports (question_id, user_id, reason, description) VALUES ($1, $2, $3, $4)',
            [questionId, userId, errorType, details]
        );
        res.status(200).json({ message: "Erro reportado com sucesso. Agradecemos sua colaboração." });
    } catch (err) {
        console.error('Erro ao reportar:', err);
        res.status(500).json({ message: 'Erro ao registrar o reporte.' });
    }
});

// Report + AI-assisted correction suggestion
app.post('/report-error-correct', authenticateToken, async (req, res) => {
    const { questionIndex, question, details } = req.body;
    const userId = req.user.id;
    try {
        // Create reports table if it doesn't exist
        await db.query(`
            CREATE TABLE IF NOT EXISTS reports (
                id SERIAL PRIMARY KEY,
                question_id INTEGER REFERENCES questions(id) ON DELETE CASCADE,
                user_id INTEGER,
                reason TEXT,
                description TEXT,
                status TEXT DEFAULT 'pending',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `);
        
        // persist the report (question may not have DB id in this flow)
        const qid = question && question.id ? question.id : null;
        await db.query(
            'INSERT INTO reports (question_id, user_id, reason, description) VALUES ($1, $2, $3, $4)',
            [qid, userId, 'user_report', details]
        );

        // Ask the generative model for a suggested correction: provide question, options, claimed answer
        // Prompt the model to return a short suggestion explaining the issue and a corrected answer if applicable.
        const model = genAI.getGenerativeModel({ model: "gemini-1.5" });
        const prompt = `Você é um assistente que corrige questões de múltipla escolha. Aqui está a questão reportada:\n\n${JSON.stringify(question)}\n\nRelato do usuário: ${details}\n\nVerifique se a alternativa correta está correta e, se não estiver, indique qual alternativa (A-E) deveria ser a correta e explique em 2-3 linhas por que, citando referências conceituais (se aplicável). Responda apenas com JSON: {"correct": "A|B|C|D|E|null", "explanation": "..."}`;
        const result = await model.generateContent(prompt);
        const responseText = result.response.text();
        let suggestion = null;
        try {
            const match = responseText.match(/\{[\s\S]*\}/);
            if (match) suggestion = JSON.parse(match[0]);
            else suggestion = { raw: responseText };
        } catch (e) { suggestion = { raw: responseText }; }

        res.status(200).json({ message: 'Reporte recebido', suggestion });
    } catch (err) {
        // Log full error for diagnosis but return a friendly success-like response
        console.error('report-error-correct failed (AI or DB step):', err && (err.stack || err.message) ? (err.stack || err.message) : err);
        // If DB insertion succeeded but AI failed, we still want to thank the user and avoid alarming message in UI.
        res.status(200).json({ message: 'Reporte recebido. A sugestão automática não está disponível no momento.' });
    }
});

// ROTAS DE ADMIN
app.post('/admin/broadcast', authenticateToken, authorizeAdmin, upload.single('image'), async (req, res) => {
    const { message } = req.body;
    const file = req.file;
    if (!message && !file) {
        return res.status(400).json({ message: "É necessário enviar uma mensagem ou uma imagem." });
    }
    let imageUrl = null;
    if (file) {
        try {
            const formData = new FormData();
            formData.append('image', fs.createReadStream(file.path));
            const response = await axios.post(`https://api.imgbb.com/1/upload?key=${IMGBB_API_KEY}`, formData, { headers: formData.getHeaders() });
            imageUrl = response.data.data.url;
        } catch (error) {
            console.error("Erro no upload para ImgBB:", error.response?.data);
            return res.status(500).json({ message: "Erro ao processar a imagem." });
        } finally {
            if (file && file.path) { fs.unlinkSync(file.path); }
        }
    }
    globalMessage = { content: message || '', imageUrl: imageUrl, timestamp: new Date() };
    setTimeout(() => { globalMessage = null; }, 60000);
    res.status(200).json({ message: "Mensagem global enviada com sucesso!" });
});

app.get('/admin/sessions', authenticateToken, authorizeAdmin, (req, res) => {
    res.status(200).json(activeSessions);
});

app.get('/admin/users', authenticateToken, authorizeAdmin, async (req, res) => {
    try {
        // Verificar se as colunas existem antes de fazer a query
        await db.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS google_id TEXT`);
        await db.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS facebook_id TEXT`);
        await db.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS name TEXT`);
        await db.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS email TEXT`);
        await db.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS is_pay BOOLEAN DEFAULT false`);
        await db.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS subscription_expires_at TIMESTAMP`);
        await db.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS last_quiz_date DATE`);
        await db.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS daily_quiz_count INTEGER DEFAULT 0`);
        
        const result = await db.query('SELECT id, name, username, email, role, is_pay, subscription_expires_at, last_quiz_date, daily_quiz_count FROM users ORDER BY id ASC');
        res.status(200).json(result.rows);
    } catch (err) {
        console.error("Erro ao buscar usuários:", err);
        console.error("Stack trace:", err.stack);
        res.status(500).json({ message: 'Erro ao buscar usuários.', error: err.message });
    }
});

app.put('/admin/users/:id', authenticateToken, authorizeAdmin, async (req, res) => {
    const { id } = req.params;
    const { is_pay, subscription_expires_at } = req.body;

    if (typeof is_pay !== 'boolean' && subscription_expires_at === undefined) {
        return res.status(400).json({ message: "Pelo menos um campo (is_pay ou subscription_expires_at) deve ser fornecido." });
    }

    try {
        const updates = [];
        const values = [];
        let queryIndex = 1;

        if (typeof is_pay === 'boolean') {
            updates.push(`is_pay = $${queryIndex++}`);
            values.push(is_pay);
        }

        if (subscription_expires_at !== undefined) {
            // Permite definir a data como nula
            if (subscription_expires_at === '' || subscription_expires_at === null) {
                updates.push(`subscription_expires_at = NULL`);
            } else {
                updates.push(`subscription_expires_at = $${queryIndex++}`);
                values.push(subscription_expires_at);
            }
        }

        if (updates.length === 0) {
            // Isso pode acontecer se subscription_expires_at for undefined e is_pay não for booleano
            return res.status(400).json({ message: "Nenhum campo válido para atualização." });
        }

        values.push(id);
        const query = `UPDATE users SET ${updates.join(', ')} WHERE id = $${queryIndex} RETURNING id, name, username, email, role, is_pay, subscription_expires_at`;

        const result = await db.query(query, values);

        if (result.rows.length === 0) {
            return res.status(404).json({ message: "Usuário não encontrado." });
        }

        res.status(200).json(result.rows[0]);
    } catch (err) {
        console.error(`Erro ao atualizar usuário ${id}:`, err);
        res.status(500).json({ message: 'Erro interno no servidor ao atualizar o usuário.' });
    }
});

app.post('/admin/message', authenticateToken, authorizeAdmin, (req, res) => {
    const { message } = req.body;
    globalMessage = message;
    setTimeout(() => { globalMessage = null; }, 60000);
    res.status(200).json({ message: "Mensagem global enviada com sucesso!" });
});

app.get('/admin/reports', authenticateToken, authorizeAdmin, async (req, res) => {
    try {
        console.log('[REPORTS] Requisição de reportes recebida');
        
        // Create reports table if it doesn't exist
        await db.query(`
            CREATE TABLE IF NOT EXISTS reports (
                id SERIAL PRIMARY KEY,
                question_id INTEGER REFERENCES questions(id) ON DELETE CASCADE,
                user_id INTEGER,
                reason TEXT,
                description TEXT,
                status TEXT DEFAULT 'pending',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `);
        
        console.log('[REPORTS] Tabela reports criada/verificada');
        
        // Verificar se a coluna status existe e adicioná-la se necessário
        try {
            await db.query(`
                ALTER TABLE reports 
                ADD COLUMN IF NOT EXISTS status TEXT DEFAULT 'pending'
            `);
            console.log('[REPORTS] Coluna status verificada/adicionada');
        } catch (alterError) {
            console.log('[REPORTS] Erro ao alterar tabela (normal se já existir):', alterError.message);
        }
        
        // Query simplificada que funciona mesmo sem algumas colunas
        const result = await db.query(`
            SELECT 
                r.id, 
                r.question_id, 
                COALESCE(r.status, 'pending') as status,
                COALESCE(r.reason, 'Não especificado') as error_type, 
                COALESCE(r.description, 'Sem descrição') as details, 
                COALESCE(q.question, 'Questão não encontrada') as question, 
                COALESCE(u.username, 'Anônimo') as reported_by, 
                r.created_at as reported_at 
            FROM reports r
            LEFT JOIN questions q ON r.question_id = q.id
            LEFT JOIN users u ON r.user_id = u.id
            ORDER BY r.created_at DESC LIMIT 20
        `);
        
        console.log('[REPORTS] Query executada, reportes encontrados:', result.rows.length);
        res.status(200).json(result.rows);
    } catch (err) {
        console.error('Erro GET /admin/reports', err);
        res.status(500).json({ message: 'Erro ao buscar reportes.', error: err.message });
    }
});

// Admin: criar reportes de teste
app.post('/admin/create-test-reports', authenticateToken, authorizeAdmin, async (req, res) => {
    try {
        console.log('[REPORTS] Criando reportes de teste...');
        
        // Buscar algumas questões para criar reportes
        const questionsResult = await db.query('SELECT id FROM questions LIMIT 3');
        
        if (questionsResult.rows.length === 0) {
            return res.status(404).json({ message: 'Nenhuma questão encontrada para criar reportes.' });
        }
        
        const testReports = [
            {
                question_id: questionsResult.rows[0].id,
                reason: 'Erro de gramática',
                description: 'A questão contém erros de gramática que podem confundir os candidatos.',
                user_id: null
            },
            {
                question_id: questionsResult.rows[0].id,
                reason: 'Resposta incorreta',
                description: 'A resposta marcada como correta parece estar errada.',
                user_id: null
            }
        ];
        
        if (questionsResult.rows.length > 1) {
            testReports.push({
                question_id: questionsResult.rows[1].id,
                reason: 'Enunciado confuso',
                description: 'O enunciado da questão não está claro.',
                user_id: null
            });
        }
        
        const createdReports = [];
        for (const report of testReports) {
            const result = await db.query(`
                INSERT INTO reports (question_id, reason, description, user_id, status)
                VALUES ($1, $2, $3, $4, 'pending')
                RETURNING id
            `, [report.question_id, report.reason, report.description, report.user_id]);
            
            createdReports.push(result.rows[0].id);
        }
        
        console.log('[REPORTS] Reportes de teste criados:', createdReports);
        res.status(200).json({ 
            message: 'Reportes de teste criados com sucesso!', 
            created_ids: createdReports 
        });
    } catch (err) {
        console.error('Erro ao criar reportes de teste:', err);
        res.status(500).json({ message: 'Erro ao criar reportes de teste.', error: err.message });
    }
});

// Admin: Dashboard Metrics
app.get('/admin/dashboard/metrics', authenticateToken, authorizeAdmin, async (req, res) => {
    try {
        console.log('[METRICS] Calculando métricas do dashboard...');
        
        // Métricas básicas
        const totalUsersResult = await db.query('SELECT COUNT(*) as count FROM users');
        const totalQuestionsResult = await db.query('SELECT COUNT(*) as count FROM questions');
        const totalCategoriesResult = await db.query('SELECT COUNT(*) as count FROM categories');
        const totalThemesResult = await db.query('SELECT COUNT(*) as count FROM themes');
        const totalReportsResult = await db.query('SELECT COUNT(*) as count FROM reports');
        
        // Usuários ativos (últimos 30 dias)
        const activeUsersResult = await db.query(`
            SELECT COUNT(DISTINCT user_id) as count 
            FROM quiz_sessions 
            WHERE created_at > CURRENT_DATE - INTERVAL '30 days'
        `);
        
        // Questões por nível de dificuldade
        const questionsByDifficultyResult = await db.query(`
            SELECT difficulty, COUNT(*) as count 
            FROM questions 
            GROUP BY difficulty 
            ORDER BY difficulty
        `);
        
        // Questões por categoria (top 10)
        const questionsByCategoryResult = await db.query(`
            SELECT c.name, COUNT(q.id) as count 
            FROM categories c
            LEFT JOIN questions q ON c.id = q.category_id
            GROUP BY c.id, c.name
            ORDER BY count DESC
            LIMIT 10
        `);
        
        // Sessões de quiz por dia (últimos 7 dias)
        const sessionsPerDayResult = await db.query(`
            SELECT 
                DATE(created_at) as date,
                COUNT(*) as count
            FROM quiz_sessions 
            WHERE created_at > CURRENT_DATE - INTERVAL '7 days'
            GROUP BY DATE(created_at)
            ORDER BY date DESC
        `);
        
        // Relatórios pendentes por tipo
        const reportsByStatusResult = await db.query(`
            SELECT status, COUNT(*) as count 
            FROM reports 
            GROUP BY status 
            ORDER BY status
        `);
        
        // Top 5 usuários mais ativos
        const topUsersResult = await db.query(`
            SELECT 
                u.username,
                u.email,
                COUNT(qs.id) as quiz_count,
                MAX(qs.created_at) as last_activity
            FROM users u
            LEFT JOIN quiz_sessions qs ON u.id = qs.user_id
            WHERE u.is_admin = false
            GROUP BY u.id, u.username, u.email
            ORDER BY quiz_count DESC, last_activity DESC
            LIMIT 5
        `);
        
        // Performance geral dos usuários
        const performanceStats = await db.query(`
            SELECT 
                AVG(score) as avg_score,
                MIN(score) as min_score,
                MAX(score) as max_score,
                COUNT(*) as total_sessions
            FROM quiz_sessions 
            WHERE score IS NOT NULL
        `);
        
        // Questões com mais reportes
        const mostReportedQuestionsResult = await db.query(`
            SELECT 
                q.id,
                q.question,
                COUNT(r.id) as report_count
            FROM questions q
            JOIN reports r ON q.id = r.question_id
            GROUP BY q.id, q.question
            ORDER BY report_count DESC
            LIMIT 5
        `);
        
        // Taxa de crescimento de usuários (últimos 30 dias vs 30 dias anteriores)
        const growthRateResult = await db.query(`
            SELECT 
                COUNT(CASE WHEN created_at > CURRENT_DATE - INTERVAL '30 days' THEN 1 END) as new_users_last_30,
                COUNT(CASE WHEN created_at BETWEEN CURRENT_DATE - INTERVAL '60 days' AND CURRENT_DATE - INTERVAL '30 days' THEN 1 END) as new_users_prev_30
            FROM users
        `);
        
        const growthRate = growthRateResult.rows[0];
        const userGrowthRate = growthRate.new_users_prev_30 > 0 
            ? ((growthRate.new_users_last_30 - growthRate.new_users_prev_30) / growthRate.new_users_prev_30 * 100).toFixed(2)
            : growthRate.new_users_last_30 > 0 ? 100 : 0;
        
        // Compilar todas as métricas
        const metrics = {
            overview: {
                totalUsers: parseInt(totalUsersResult.rows[0].count),
                totalQuestions: parseInt(totalQuestionsResult.rows[0].count),
                totalCategories: parseInt(totalCategoriesResult.rows[0].count),
                totalThemes: parseInt(totalThemesResult.rows[0].count),
                totalReports: parseInt(totalReportsResult.rows[0].count),
                activeUsers: parseInt(activeUsersResult.rows[0].count),
                userGrowthRate: parseFloat(userGrowthRate)
            },
            questionStats: {
                byDifficulty: questionsByDifficultyResult.rows.map(row => ({
                    difficulty: row.difficulty || 'N/A',
                    count: parseInt(row.count)
                })),
                byCategory: questionsByCategoryResult.rows.map(row => ({
                    category: row.name,
                    count: parseInt(row.count)
                }))
            },
            activity: {
                sessionsPerDay: sessionsPerDayResult.rows.map(row => ({
                    date: row.date,
                    count: parseInt(row.count)
                })),
                topUsers: topUsersResult.rows.map(row => ({
                    username: row.username,
                    email: row.email,
                    quizCount: parseInt(row.quiz_count || 0),
                    lastActivity: row.last_activity
                }))
            },
            performance: {
                avgScore: parseFloat(performanceStats.rows[0].avg_score || 0).toFixed(2),
                minScore: parseFloat(performanceStats.rows[0].min_score || 0),
                maxScore: parseFloat(performanceStats.rows[0].max_score || 0),
                totalSessions: parseInt(performanceStats.rows[0].total_sessions || 0)
            },
            reports: {
                byStatus: reportsByStatusResult.rows.map(row => ({
                    status: row.status,
                    count: parseInt(row.count)
                })),
                mostReported: mostReportedQuestionsResult.rows.map(row => ({
                    questionId: row.id,
                    question: row.question.substring(0, 100) + (row.question.length > 100 ? '...' : ''),
                    reportCount: parseInt(row.report_count)
                }))
            },
            lastUpdated: new Date().toISOString()
        };
        
        console.log('[METRICS] Métricas calculadas com sucesso');
        res.status(200).json(metrics);
        
    } catch (err) {
        console.error('Erro ao calcular métricas do dashboard:', err);
        res.status(500).json({ 
            message: 'Erro ao calcular métricas do dashboard.', 
            error: err.message 
        });
    }
});

// Admin: list all questions with category info
app.get('/admin/questions', authenticateToken, authorizeAdmin, async (req, res) => {
    try {
        // First ensure the required columns exist
        await db.query(`ALTER TABLE questions ADD COLUMN IF NOT EXISTS category_id INTEGER`);
        await db.query(`ALTER TABLE questions ADD COLUMN IF NOT EXISTS created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP`);
        await db.query(`ALTER TABLE questions ADD COLUMN IF NOT EXISTS difficulty TEXT`);
        
        // Create reports table if it doesn't exist
        await db.query(`
            CREATE TABLE IF NOT EXISTS reports (
                id SERIAL PRIMARY KEY,
                question_id INTEGER REFERENCES questions(id) ON DELETE CASCADE,
                user_id INTEGER,
                reason TEXT,
                description TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `);
        
        // Ensure "Sem Categoria" exists and update questions without category
        let semCategoriaId;
        const categoriaResult = await db.query(`SELECT id FROM categories WHERE name = 'Sem Categoria'`);
        if (categoriaResult.rows.length === 0) {
            const insertResult = await db.query(`INSERT INTO categories (name) VALUES ('Sem Categoria') RETURNING id`);
            semCategoriaId = insertResult.rows[0].id;
        } else {
            semCategoriaId = categoriaResult.rows[0].id;
        }
        
        // Update questions without category to use "Sem Categoria"
        await db.query(`UPDATE questions SET category_id = $1 WHERE category_id IS NULL`, [semCategoriaId]);
        
        const result = await db.query(`
            SELECT 
                q.id, 
                q.theme_id, 
                q.question, 
                q.options,
                q.answer,
                q.difficulty,
                q.created_at,
                q.category_id,
                t.name as theme_name,
                COALESCE(c.name, 'Sem Categoria') as category_name,
                (SELECT COUNT(*) FROM reports r WHERE r.question_id = q.id) as report_count,
                EXISTS(SELECT 1 FROM reports r WHERE r.question_id = q.id) as reported
            FROM questions q
            LEFT JOIN themes t ON q.theme_id = t.id
            LEFT JOIN categories c ON COALESCE(t.category_id, q.category_id) = c.id
            ORDER BY COALESCE(c.name, 'Sem Categoria'), t.name, q.id DESC
        `);
        
        // Parse options from JSON string to array
        const questionsWithParsedOptions = result.rows.map(row => {
            let options = row.options;
            if (typeof options === 'string') {
                try {
                    options = JSON.parse(options);
                } catch (e) {
                    // If JSON parse fails, try to split by newlines or keep as string
                    if (options.includes('\n')) {
                        options = options.split('\n').filter(opt => opt.trim());
                    } else {
                        options = [options];
                    }
                }
            }
            return { ...row, options };
        });
        
        res.status(200).json(questionsWithParsedOptions);
    } catch (err) {
        console.error('Erro GET /admin/questions', err);
        res.status(500).json({ message: 'Erro ao buscar questões.' });
    }
});

// Admin: fetch a single question (full JSON) for inspection/edit
app.get('/admin/questions/:id', authenticateToken, authorizeAdmin, async (req, res) => {
    const qid = parseInt(req.params.id, 10);
    if (!qid) return res.status(400).json({ message: 'ID inválido.' });
    try {
        const result = await db.query('SELECT id, theme_id, question, options, answer FROM questions WHERE id = $1', [qid]);
        if (result.rowCount === 0) return res.status(404).json({ message: 'Questão não encontrada.' });
        
        const question = result.rows[0];
        let options = question.options;
        if (typeof options === 'string') {
            try {
                options = JSON.parse(options);
            } catch (e) {
                // If JSON parse fails, try to split by newlines or keep as string
                if (options.includes('\n')) {
                    options = options.split('\n').filter(opt => opt.trim());
                } else {
                    options = [options];
                }
            }
        }
        
        res.status(200).json({ ...question, options });
    } catch (err) {
        console.error('Erro GET /admin/questions/:id', err);
        res.status(500).json({ message: 'Erro ao buscar questão.' });
    }
});

// Admin: update a question record with provided JSON payload
app.put('/admin/questions/:id', authenticateToken, authorizeAdmin, express.json(), async (req, res) => {
    const qid = parseInt(req.params.id, 10);
    if (!qid) return res.status(400).json({ message: 'ID inválido.' });
    const { question, options, answer } = req.body;
    try {
        // Try to normalize options: if it's a string that contains JSON array, parse it; if array, leave as array
        let optionsToStore = options;
        if (typeof options === 'string') {
            const trimmed = options.trim();
            if (trimmed.startsWith('[') || trimmed.startsWith('{')) {
                try { optionsToStore = JSON.parse(trimmed); } catch (e) { /* keep original string */ }
            }
        }
        // If it's an array, pass as-is (node-postgres will map to JSON/array appropriately); if it's an object, stringify it
        if (Array.isArray(optionsToStore) || typeof optionsToStore === 'object') {
            // for JSON/array columns, pass JS value; if DB column is text, pg will stringify it
        }
        // ensure options are sent as a JSON string to avoid type mismatches with different DB column types
        let optionsParam = optionsToStore;
        // If it's an array, pass it directly (node-postgres will map JS arrays to Postgres array types)
        if (Array.isArray(optionsToStore)) {
            optionsParam = optionsToStore;
        } else if (typeof optionsToStore === 'object' && optionsToStore !== null) {
            // for plain objects (not arrays), store as JSON string
            try { optionsParam = JSON.stringify(optionsToStore); } catch (e) { optionsParam = String(optionsToStore); }
        }
        const result = await db.query('UPDATE questions SET question = $1, options = $2, answer = $3 WHERE id = $4 RETURNING id, theme_id, question, options, answer', [question, optionsParam, answer, qid]);
        if (result.rowCount === 0) return res.status(404).json({ message: 'Questão não encontrada.' });
        res.status(200).json(result.rows[0]);
    } catch (err) {
        console.error('Erro PUT /admin/questions/:id', err && (err.stack || err.message) ? (err.stack || err.message) : err);
        // return more detailed error to admin UI for debugging
        // include common Postgres error fields for diagnosis
        const errPayload = { message: 'Erro ao atualizar questão.' };
        try {
            if (err && err.message) errPayload.error = String(err.message);
            if (err && err.code) errPayload.code = String(err.code);
            if (err && err.detail) errPayload.detail = String(err.detail);
        } catch (e) { errPayload.error = String(err && err.message ? err.message : err); }
        res.status(500).json(errPayload);
    }
});

// Admin: delete a question
app.delete('/admin/questions/:id', authenticateToken, authorizeAdmin, async (req, res) => {
    const qid = parseInt(req.params.id, 10);
    console.log('[DELETE-QUESTION] Tentativa de exclusão da questão ID:', qid);
    console.log('[DELETE-QUESTION] User:', req.user ? req.user.id : 'undefined');
    
    if (!qid) {
        console.log('[DELETE-QUESTION] ID inválido:', req.params.id);
        return res.status(400).json({ message: 'ID inválido.' });
    }
    
    try {
        // Iniciar transação para garantir consistência
        await db.query('BEGIN');
        
        console.log('[DELETE-QUESTION] Excluindo dependências da questão...');
        
        // 1. Excluir reportes da questão
        const reportsResult = await db.query('DELETE FROM reports WHERE question_id = $1', [qid]);
        console.log('[DELETE-QUESTION] Reportes excluídos:', reportsResult.rowCount);
        
        // 2. Excluir histórico de quiz (se existir)
        try {
            const historyResult = await db.query('DELETE FROM quiz_history WHERE question_id = $1', [qid]);
            console.log('[DELETE-QUESTION] Histórico excluído:', historyResult.rowCount);
        } catch (err) {
            console.log('[DELETE-QUESTION] Tabela quiz_history não existe ou erro:', err.message);
        }
        
        // 3. Excluir respostas dos usuários (se existir)
        try {
            const answersResult = await db.query('DELETE FROM user_answers WHERE question_id = $1', [qid]);
            console.log('[DELETE-QUESTION] Respostas excluídas:', answersResult.rowCount);
        } catch (err) {
            console.log('[DELETE-QUESTION] Tabela user_answers não existe ou erro:', err.message);
        }
        
        // 4. Excluir outras possíveis referências
        try {
            const statisticsResult = await db.query('DELETE FROM question_statistics WHERE question_id = $1', [qid]);
            console.log('[DELETE-QUESTION] Estatísticas excluídas:', statisticsResult.rowCount);
        } catch (err) {
            console.log('[DELETE-QUESTION] Tabela question_statistics não existe ou erro:', err.message);
        }
        
        console.log('[DELETE-QUESTION] Excluindo questão...');
        // Finalmente, excluir a questão
        const result = await db.query('DELETE FROM questions WHERE id = $1 RETURNING id', [qid]);
        console.log('[DELETE-QUESTION] Resultado da exclusão:', result.rowCount, result.rows);
        
        if (result.rowCount === 0) {
            console.log('[DELETE-QUESTION] Questão não encontrada');
            await db.query('ROLLBACK');
            return res.status(404).json({ message: 'Questão não encontrada.' });
        }
        
        // Confirmar transação
        await db.query('COMMIT');
        console.log('[DELETE-QUESTION] Questão excluída com sucesso');
        res.status(200).json({ message: 'Questão excluída com sucesso.', id: qid });
    } catch (err) {
        // Desfazer transação em caso de erro
        await db.query('ROLLBACK');
        console.error('Erro DELETE /admin/questions/:id', err);
        res.status(500).json({ 
            message: 'Erro ao excluir questão.', 
            error: err.message,
            detail: err.detail || 'Erro interno do servidor'
        });
    }
});

// Admin: verificar dependências de uma questão (para debug)
app.get('/admin/questions/:id/dependencies', authenticateToken, authorizeAdmin, async (req, res) => {
    const qid = parseInt(req.params.id, 10);
    
    if (!qid) {
        return res.status(400).json({ message: 'ID inválido.' });
    }
    
    try {
        const dependencies = {};
        
        // Verificar reportes
        try {
            const reports = await db.query('SELECT COUNT(*) as count FROM reports WHERE question_id = $1', [qid]);
            dependencies.reports = parseInt(reports.rows[0].count);
        } catch (err) {
            dependencies.reports = 'N/A';
        }
        
        // Verificar histórico de quiz
        try {
            const history = await db.query('SELECT COUNT(*) as count FROM quiz_history WHERE question_id = $1', [qid]);
            dependencies.quiz_history = parseInt(history.rows[0].count);
        } catch (err) {
            dependencies.quiz_history = 'N/A';
        }
        
        // Verificar respostas dos usuários
        try {
            const answers = await db.query('SELECT COUNT(*) as count FROM user_answers WHERE question_id = $1', [qid]);
            dependencies.user_answers = parseInt(answers.rows[0].count);
        } catch (err) {
            dependencies.user_answers = 'N/A';
        }
        
        // Verificar estatísticas
        try {
            const stats = await db.query('SELECT COUNT(*) as count FROM question_statistics WHERE question_id = $1', [qid]);
            dependencies.question_statistics = parseInt(stats.rows[0].count);
        } catch (err) {
            dependencies.question_statistics = 'N/A';
        }
        
        // Verificar constraint violations usando query system tables
        try {
            const constraints = await db.query(`
                SELECT 
                    tc.constraint_name, 
                    tc.table_name,
                    kcu.column_name,
                    ccu.table_name AS foreign_table_name,
                    ccu.column_name AS foreign_column_name 
                FROM 
                    information_schema.table_constraints AS tc 
                    JOIN information_schema.key_column_usage AS kcu
                      ON tc.constraint_name = kcu.constraint_name
                      AND tc.table_schema = kcu.table_schema
                    JOIN information_schema.constraint_column_usage AS ccu
                      ON ccu.constraint_name = tc.constraint_name
                      AND ccu.table_schema = tc.table_schema
                WHERE tc.constraint_type = 'FOREIGN KEY' 
                AND ccu.table_name = 'questions'
                AND ccu.column_name = 'id'
            `);
            dependencies.foreign_key_constraints = constraints.rows;
        } catch (err) {
            dependencies.foreign_key_constraints = 'Error: ' + err.message;
        }
        
        res.status(200).json(dependencies);
    } catch (err) {
        console.error('Erro ao verificar dependências:', err);
        res.status(500).json({ message: 'Erro ao verificar dependências.', error: err.message });
    }
});

// Admin: duplicate a question
// Admin: mark question reports as resolved
app.put('/admin/questions/:id/resolve-reports', authenticateToken, authorizeAdmin, async (req, res) => {
    const qid = parseInt(req.params.id, 10);
    if (!qid) return res.status(400).json({ message: 'ID inválido.' });
    
    try {
        const result = await db.query('DELETE FROM reports WHERE question_id = $1 RETURNING id', [qid]);
        res.status(200).json({ 
            message: 'Reports resolvidos com sucesso.',
            resolved_count: result.rowCount
        });
    } catch (err) {
        console.error('Erro PUT /admin/questions/:id/resolve-reports', err);
        res.status(500).json({ message: 'Erro ao resolver reports.' });
    }
});

app.post('/admin/themes', authenticateToken, authorizeAdmin, upload.single('pdfFile'), async (req, res) => {
    const { themeName, questionCount, categoryId, sourceType, searchQuery } = req.body;
    const file = req.file;
    if (!themeName || !questionCount) {
        return res.status(400).json({ message: "Nome do tema e quantidade de questões são obrigatórios." });
    }
    try {
        let generatedQuestions = [];
        const difficulty = (req.body && req.body.difficulty) ? String(req.body.difficulty) : 'easy';
        if (String(sourceType || 'pdf') === 'web') {
            // Use Gemini only: ask the model to generate questions from the topic directly.
            const term = searchQuery || themeName;
            console.log('Admin web-source generation via Gemini for term:', term, 'difficulty:', difficulty);
            generatedQuestions = await generateQuestionsFromTopic(term, questionCount, difficulty);
        } else {
            if (!file) return res.status(400).json({ message: "Arquivo PDF é obrigatório quando a fonte for PDF." });
            const dataBuffer = fs.readFileSync(file.path);
            const data = await pdfParse(dataBuffer);
            // default generation
            generatedQuestions = await generateQuestionsFromText(data.text, questionCount);
            // if non-easy, attempt difficulty-aware generation
            if (difficulty && difficulty !== 'easy') {
                try {
                    const prompt = buildPromptForDifficulty(data.text, questionCount, difficulty);
                    const model = genAI.getGenerativeModel({ model: "gemini-1.5-flash-latest" });
                    const result = await model.generateContent(prompt);
                    const responseText = result.response.text();
                    const jsonMatch = responseText.match(/(\[[\s\S]*\])/);
                    if (jsonMatch && jsonMatch[0]) generatedQuestions = JSON.parse(jsonMatch[0]);
                } catch (e) { console.warn('Difficulty-aware generation failed, using default generation', e && e.message ? e.message : e); }
            }
        }
        // ensure themes table has category_id column (idempotent)
        await db.query(`ALTER TABLE themes ADD COLUMN IF NOT EXISTS category_id INTEGER NULL`);
        const themeResult = await db.query('INSERT INTO themes (name, category_id) VALUES ($1, $2) RETURNING id', [themeName, categoryId || null]);
        const newThemeId = themeResult.rows[0].id;
        for (const q of generatedQuestions) {
            try { 
                await db.query(`ALTER TABLE questions ADD COLUMN IF NOT EXISTS difficulty TEXT`); 
                await db.query(`ALTER TABLE questions ADD COLUMN IF NOT EXISTS category_id INTEGER`);
                await db.query(`ALTER TABLE questions ADD COLUMN IF NOT EXISTS created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP`);
            } catch (e) {}
            await db.query(
                'INSERT INTO questions (theme_id, question, options, answer, difficulty, category_id) VALUES ($1, $2, $3, $4, $5, $6)',
                [newThemeId, q.question, JSON.stringify(q.options), resolveAnswerText(q), difficulty, categoryId || null]
            );
        }
        res.status(201).json({ message: `Tema '${themeName}' e ${generatedQuestions.length} questões foram adicionadas.` });
    } catch (err) {
        console.error("Erro no upload de tema:", err && err.stack ? err.stack : err);
        const userMessage = (err && err.message) ? String(err.message) : 'Erro no servidor ao processar o arquivo.';
        // include hint for admin in logs, but return a concise message to UI
    res.status(500).json({ message: userMessage, error: (err && err.message) ? String(err.message) : String(err) });
    } finally {
        if (file && file.path) {
            fs.unlinkSync(file.path);
        }
    }
});

app.delete('/admin/themes/:id', authenticateToken, authorizeAdmin, async (req, res) => {
    const { id } = req.params;
    try {
        const questionsResult = await db.query('SELECT id FROM questions WHERE theme_id = $1', [id]);
        const questionIds = questionsResult.rows.map(q => q.id);
        if (questionIds.length > 0) {
            await db.query('DELETE FROM user_answers WHERE question_id = ANY($1::int[])', [questionIds]);
        }
        const result = await db.query('DELETE FROM themes WHERE id = $1 RETURNING name', [id]);
        if (result.rowCount === 0) {
            return res.status(404).json({ message: "Tema não encontrado." });
        }
        res.status(200).json({ message: `Tema '${result.rows[0].name}' e suas questões foram apagados com sucesso.` });
    } catch (err) {
        console.error("Erro ao apagar tema:", err);
        res.status(500).json({ message: 'Erro no servidor ao apagar o tema.' });
    }
});

// Update theme (assign category)
app.put('/admin/themes/:id', authenticateToken, authorizeAdmin, express.json(), async (req, res) => {
    const themeId = parseInt(req.params.id, 10);
    const { categoryId } = req.body;
    try {
        // Ensure column exists
        await db.query(`ALTER TABLE themes ADD COLUMN IF NOT EXISTS category_id INTEGER NULL`);
        const result = await db.query('UPDATE themes SET category_id = $1 WHERE id = $2 RETURNING id, name, category_id', [categoryId || null, themeId]);
        if (result.rowCount === 0) return res.status(404).json({ message: 'Tema não encontrado.' });
        res.status(200).json(result.rows[0]);
    } catch (err) {
        console.error('Erro ao atualizar tema:', err);
        res.status(500).json({ message: 'Erro ao atualizar tema.' });
    }
});

// Append questions to an existing theme (admin)
app.post('/admin/themes/:id/add', authenticateToken, authorizeAdmin, upload.single('pdfFile'), async (req, res) => {
    console.log('[HANDLER] Entered POST /admin/themes/:id/add');
    console.log('[HANDLER] Headers:', JSON.stringify(req.headers));
    // Note: multipart bodies are handled by multer; we can at least log that the middleware ran
    try { console.log('[HANDLER] Content-Type:', req.get('content-type')); } catch (e) {}
    const themeId = parseInt(req.params.id, 10);
    const { questionCount, sourceType, searchQuery } = req.body;
    const file = req.file;
    if (!themeId || !questionCount) return res.status(400).json({ message: 'ID do tema e quantidade de questões são obrigatórios.' });
    try {
        // ensure theme exists
        const tRes = await db.query('SELECT id FROM themes WHERE id = $1', [themeId]);
        if (tRes.rowCount === 0) return res.status(404).json({ message: 'Tema não encontrado.' });

        let generated = [];
        const difficulty = (req.body && req.body.difficulty) ? String(req.body.difficulty) : 'easy';
        if (String(sourceType || 'pdf') === 'web') {
            const term = searchQuery || '';
            generated = await generateQuestionsFromTopic(term || `Tópico para tema ${themeId}`, questionCount, difficulty);
        } else {
            if (!file) return res.status(400).json({ message: 'Arquivo PDF é obrigatório quando a fonte for PDF.' });
            const data = await pdfParse(fs.readFileSync(file.path));
            generated = await generateQuestionsFromText(data.text, questionCount);
            // generateQuestionsFromText currently uses default easy prompt; for PDF source we can also customize by difficulty
            if (difficulty && difficulty !== 'easy') {
                // re-run a targeted generation with difficulty-aware prompt if desired (light approach: prepend difficulty note)
                const prompt = buildPromptForDifficulty(data.text, questionCount, difficulty);
                try {
                    const model = genAI.getGenerativeModel({ model: "gemini-1.5-flash-latest" });
                    const result = await model.generateContent(prompt);
                    const responseText = result.response.text();
                    const jsonMatch = responseText.match(/(\[[\s\S]*\])/);
                    if (jsonMatch && jsonMatch[0]) generated = JSON.parse(jsonMatch[0]);
                } catch (e) {
                    console.warn('Difficulty-specific generation fallback failed, using default generated set', e && e.message ? e.message : e);
                }
            }
        }

        // insert generated questions appended to existing ones
        for (const q of generated) {
            // ensure questions table has difficulty, category_id and created_at columns
            try { 
                await db.query(`ALTER TABLE questions ADD COLUMN IF NOT EXISTS difficulty TEXT`); 
                await db.query(`ALTER TABLE questions ADD COLUMN IF NOT EXISTS category_id INTEGER`);
                await db.query(`ALTER TABLE questions ADD COLUMN IF NOT EXISTS created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP`);
            } catch (e) {}
            
            // Get the category_id from theme if available
            const themeCategoryId = categoryId || null;
            
            await db.query('INSERT INTO questions (theme_id, question, options, answer, difficulty, category_id) VALUES ($1,$2,$3,$4,$5,$6)', 
                [themeId, q.question, JSON.stringify(q.options), resolveAnswerText(q), difficulty, themeCategoryId]);
        }
        res.status(201).json({ message: `Adicionadas ${generated.length} questões ao tema ${themeId}.` });
    } catch (err) {
        console.error('Erro ao adicionar questões ao tema:', err);
    res.status(500).json({ message: (err && err.message) ? String(err.message) : 'Erro interno.' });
    } finally {
        if (file && file.path) fs.unlinkSync(file.path);
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
        
        // Get theme info to get category_id
        const themeResult = await db.query('SELECT category_id FROM themes WHERE id = $1', [id]);
        const themeCategoryId = themeResult.rows[0]?.category_id || null;
        
        for (const q of newQuestions) {
            try { 
                await db.query(`ALTER TABLE questions ADD COLUMN IF NOT EXISTS category_id INTEGER`);
                await db.query(`ALTER TABLE questions ADD COLUMN IF NOT EXISTS created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP`);
            } catch (e) {}
            await db.query(
                'INSERT INTO questions (theme_id, question, options, answer, category_id) VALUES ($1, $2, $3, $4, $5)',
                [id, q.question, JSON.stringify(q.options), resolveAnswerText(q), themeCategoryId]
            );
        }
        res.status(200).json({ message: `Tema resetado com ${newQuestions.length} novas questões.` });
    } catch (err) {
        res.status(500).json({ message: 'Erro ao resetar tema.', error: err.message });
    } finally {
        if (file && file.path) { fs.unlinkSync(file.path); }
    }
});

// --- CATEGORIES: Admin-managed hierarchical categories (up to 2 levels below root)
app.get('/admin/categories', authenticateToken, authorizeAdmin, async (req, res) => {
    try {
        // ensure table exists
        await db.query(`CREATE TABLE IF NOT EXISTS categories (
            id SERIAL PRIMARY KEY,
            name TEXT NOT NULL,
            parent_id INTEGER NULL
        )`);
        const result = await db.query('SELECT id, name, parent_id FROM categories ORDER BY id ASC');
        const rows = result.rows;
        // build tree
        const map = new Map();
        rows.forEach(r => map.set(r.id, { id: r.id, name: r.name, parentId: r.parent_id, children: [] }));
        const roots = [];
        map.forEach(node => {
            if (node.parentId) {
                const parent = map.get(node.parentId);
                if (parent) parent.children.push(node);
                else roots.push(node);
            } else roots.push(node);
        });
        res.status(200).json(roots);
    } catch (err) {
        console.error('Erro categories GET:', err);
        res.status(500).json({ message: 'Erro ao listar categorias.' });
    }
});

// Public endpoint for frontend to fetch categories (hierarchical)
app.get('/categories', authenticateToken, async (req, res) => {
    try {
        await db.query(`CREATE TABLE IF NOT EXISTS categories (
            id SERIAL PRIMARY KEY,
            name TEXT NOT NULL,
            parent_id INTEGER NULL
        )`);
        const result = await db.query('SELECT id, name, parent_id FROM categories ORDER BY id ASC');
        const rows = result.rows;
        const map = new Map();
        rows.forEach(r => map.set(r.id, { id: r.id, name: r.name, parentId: r.parent_id, children: [] }));
        const roots = [];
        map.forEach(node => {
            if (node.parentId) {
                const parent = map.get(node.parentId);
                if (parent) parent.children.push(node);
                else roots.push(node);
            } else roots.push(node);
        });
        res.status(200).json(roots);
    } catch (err) {
        console.error('Erro categories (public) GET:', err);
        res.status(500).json({ message: 'Erro ao listar categorias.' });
    }
});

app.post('/admin/categories', authenticateToken, authorizeAdmin, express.json(), async (req, res) => {
    const { name, parentId } = req.body;
    if (!name) return res.status(400).json({ message: 'Nome é obrigatório' });
    try {
        await db.query(`CREATE TABLE IF NOT EXISTS categories (
            id SERIAL PRIMARY KEY,
            name TEXT NOT NULL,
            parent_id INTEGER NULL
        )`);
        // check depth if parentId provided
        if (parentId) {
            // compute depth by walking up
            let depth = 0;
            let current = parentId;
            while (current && depth <= 3) {
                const r = await db.query('SELECT parent_id FROM categories WHERE id = $1', [current]);
                if (!r.rows[0]) break;
                current = r.rows[0].parent_id;
                depth++;
            }
            if (depth >= 2) {
                return res.status(400).json({ message: 'Profundidade máxima atingida (até 2 níveis abaixo do root).' });
            }
        }
        const insert = await db.query('INSERT INTO categories (name, parent_id) VALUES ($1, $2) RETURNING id, name, parent_id', [name, parentId || null]);
        res.status(201).json(insert.rows[0]);
    } catch (err) {
        console.error('Erro categories POST:', err);
        res.status(500).json({ message: 'Erro ao criar categoria.' });
    }
});

// Admin: rename/update category
app.put('/admin/categories/:id', authenticateToken, authorizeAdmin, express.json(), async (req, res) => {
    const id = parseInt(req.params.id, 10);
    const { name } = req.body;
    
    if (!name || !name.trim()) {
        return res.status(400).json({ message: 'Nome da categoria é obrigatório.' });
    }
    
    try {
        const result = await db.query('UPDATE categories SET name = $1 WHERE id = $2 RETURNING *', [name.trim(), id]);
        if (result.rowCount === 0) {
            return res.status(404).json({ message: 'Categoria não encontrada.' });
        }
        
        res.status(200).json(result.rows[0]);
    } catch (err) {
        console.error('Erro categories PUT:', err);
        res.status(500).json({ message: 'Erro ao renomear categoria.' });
    }
});

app.delete('/admin/categories/:id', authenticateToken, authorizeAdmin, async (req, res) => {
    const id = parseInt(req.params.id, 10);
    try {
        await db.query('DELETE FROM categories WHERE id = $1 OR parent_id = $1', [id]);
        res.status(200).json({ message: 'Categoria e subcategorias removidas.' });
    } catch (err) {
        console.error('Erro categories DELETE:', err);
        res.status(500).json({ message: 'Erro ao apagar categoria.' });
    }
});

// --- PER-USER TAGS (store tags per user) ---
app.get('/account/tags', authenticateToken, async (req, res) => {
    try {
        await db.query(`CREATE TABLE IF NOT EXISTS user_tags (
            user_id INTEGER PRIMARY KEY,
            tags JSONB
        )`);
        const r = await db.query('SELECT tags FROM user_tags WHERE user_id = $1', [req.user.id]);
        if (!r.rows[0]) return res.status(200).json([]);
        return res.status(200).json(r.rows[0].tags || []);
    } catch (err) {
        console.error('Erro account/tags GET:', err);
        res.status(500).json({ message: 'Erro ao buscar tags do usuário.' });
    }
});

app.put('/account/tags', authenticateToken, express.json(), async (req, res) => {
    const { tags } = req.body;
    if (!Array.isArray(tags)) return res.status(400).json({ message: 'Tags devem ser um array.' });
    try {
        await db.query(`CREATE TABLE IF NOT EXISTS user_tags (
            user_id INTEGER PRIMARY KEY,
            tags JSONB
        )`);
        await db.query('INSERT INTO user_tags (user_id, tags) VALUES ($1, $2) ON CONFLICT (user_id) DO UPDATE SET tags = EXCLUDED.tags', [req.user.id, tags]);
        res.status(200).json({ message: 'Tags atualizadas.' });
    } catch (err) {
        console.error('Erro account/tags PUT:', err);
        res.status(500).json({ message: 'Erro ao atualizar tags do usuário.' });
    }
});

// --- INICIAR O SERVIDOR ---
// Lightweight health endpoint
app.get('/health', async (req, res) => {
    try {
        const ok = await db.testConnection();
        if (!ok) return res.status(500).json({ status: 'db_unreachable' });
        return res.status(200).json({ status: 'ok', uptime: process.uptime() });
    } catch (err) {
        console.error('Health check error:', err && err.message ? err.message : err);
        return res.status(500).json({ status: 'error' });
    }
});

app.listen(PORT, () => {
    console.log(`Servidor rodando e ouvindo na porta ${PORT}`);
});

// Lightweight migration: mark existing questions with null difficulty as 'easy'
(async function ensureExistingQuestionsHaveDifficulty() {
    try {
        await db.query(`ALTER TABLE questions ADD COLUMN IF NOT EXISTS difficulty TEXT`);
        await db.query(`UPDATE questions SET difficulty = 'easy' WHERE difficulty IS NULL OR difficulty = ''`);
        console.log('Migration: ensured existing questions have difficulty=easy');
    } catch (e) {
        console.warn('Migration failed (non-fatal):', e && e.message ? e.message : e);
    }
})();
