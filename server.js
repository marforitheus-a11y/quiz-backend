require('dotenv').config();
// arquivo: server.js (versão final com JWT)
const multer = require('multer');
const path = require('path'); // Módulo para lidar com caminhos de arquivos
const fs = require('fs'); // Módulo para interagir com o sistema de arquivos
const pdfParse = require('pdf-parse');
const express = require('express');
const bcrypt = require('bcrypt');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const db = require('./db');

const app = express();
const PORT = 3000;

const JWT_SECRET = 'seu-segredo-super-secreto-e-longo-aqui-12345';
const { GoogleGenerativeAI } = require("@google/generative-ai");

// Pega a chave de API do arquivo .env
const GEMINI_API_KEY = process.env.GEMINI_API_KEY;

// Inicializa o cliente da IA
const genAI = new GoogleGenerativeAI(GEMINI_API_KEY);
// --- CONFIGURAÇÃO DO MULTER PARA UPLOAD DE ARQUIVOS ---

// Define onde os arquivos serão salvos
const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        const dir = './uploads';
        // Cria o diretório 'uploads' se ele não existir
        if (!fs.existsSync(dir)){
            fs.mkdirSync(dir);
        }
        cb(null, dir);
    },
    filename: function (req, file, cb) {
        // Define um nome único para o arquivo para evitar conflitos
        cb(null, Date.now() + '-' + file.originalname);
    }
});

// Filtro para aceitar apenas arquivos PDF
const fileFilter = (req, file, cb) => {
    if (file.mimetype === 'application/pdf') {
        cb(null, true); // Aceita o arquivo
    } else {
        cb(new Error('Formato de arquivo não suportado! Apenas PDFs são permitidos.'), false); // Rejeita o arquivo
    }
};
function authorizeAdmin(req, res, next) {
    if (req.user && req.user.role === 'admin') {
        next();
    } else {
        res.status(403).json({ message: 'Acesso negado. Apenas administradores podem acessar.' });
    }
}
// Cria a instância do multer com a configuração de storage e filtro
const upload = multer({ storage: storage, fileFilter: fileFilter });
// --- MIDDLEWARE DE AUTENTICAÇÃO ---
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


app.use(cors());
app.use(express.json());

// --- ROTAS DA API ---

app.post('/login', async (req, res) => {
    const { username, password } = req.body;
    try {
        const result = await db.query('SELECT * FROM users WHERE username = $1', [username]);
        const user = result.rows[0];
        if (!user) return res.status(401).json({ message: "Usuário ou senha inválidos." });

        const isPasswordCorrect = await bcrypt.compare(password, user.password);
        if (isPasswordCorrect) {
    // Verifica se a assinatura expirou
    if (user.subscription_expires_at && new Date(user.subscription_expires_at) < new Date()) {
        console.log(`AVISO: O usuário '${user.username}' tentou logar com uma assinatura expirada.`);
        // Em um app real, você retornaria um erro aqui:
        // return res.status(403).json({ message: "Sua assinatura expirou." });
    }

    const payload = { id: user.id, username: user.username, role: user.role };
    const token = jwt.sign(payload, JWT_SECRET, { expiresIn: '8h' });
    res.status(200).json({ message: "Login bem-sucedido!", token: token });
} else {
            res.status(401).json({ message: "Usuário ou senha inválidos." });
        }
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Erro no servidor.' });
    }
});

app.get('/themes', async (req, res) => {
    try {
        const result = await db.query('SELECT * FROM themes ORDER BY name');
        res.status(200).json(result.rows);
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Erro no servidor.' });
    }
});

app.post('/questions', async (req, res) => {
    const { themeIds, count } = req.body;
    try {
        const result = await db.query(
            'SELECT * FROM questions WHERE theme_id = ANY($1::int[]) ORDER BY RANDOM() LIMIT $2',
            [themeIds, count]
        );
        res.status(200).json(result.rows);
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Erro no servidor.' });
    }
});

// --- ROTAS DE ADMIN (PROTEGIDAS) ---

// Rota para criar um novo usuário (com validade de assinatura)
app.post('/admin/users', authenticateToken, authorizeAdmin, async (req, res) => {
    const { username, password, role, subscription_expires_at } = req.body; // Adicionamos a nova data
    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        const result = await db.query(
            'INSERT INTO users (username, password, role, subscription_expires_at) VALUES ($1, $2, $3, $4) RETURNING id, username, role, subscription_expires_at',
            [username, hashedPassword, role || 'user', subscription_expires_at || null] // Salva a data no banco
        );
        res.status(201).json({ message: "Usuário criado com sucesso!", user: result.rows[0] });
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Erro ao criar usuário.' });
    }
});
    
app.post('/admin/themes', authenticateToken, authorizeAdmin, upload.single('pdfFile'), async (req, res) => {
    // 'upload.single('pdfFile')' é o middleware do multer.
    // Ele processa um arquivo enviado no campo 'pdfFile'.

    const { themeName } = req.body; // O nome do tema vem do corpo do formulário
    const file = req.file; // As informações do arquivo salvo ficam em req.file

    if (!file) {
        return res.status(400).json({ message: "Nenhum arquivo PDF foi enviado." });
    }
    if (!themeName) {
        return res.status(400).json({ message: "O nome do tema é obrigatório." });
    }

    try {
        // 1. Extrair o texto do PDF que foi salvo
        const dataBuffer = fs.readFileSync(file.path);
        const data = await pdfParse(dataBuffer);
        const extractedText = data.text;

        // --- FUNÇÃO REAL DE IA PARA GERAR QUESTÕES ---
async function generateQuestionsFromText(text) {
    try {
        console.log("Chamando a API do Gemini para gerar questões...");

        const model = genAI.getGenerativeModel({ model: "gemini-pro" });

        // O "Prompt" é a instrução que damos à IA. Ser explícito é a chave para um bom resultado.
        const prompt = `
            Com base no seguinte texto extraído de um documento, gere 5 questões de concurso de múltipla escolha com 5 alternativas cada (A, B, C, D, E), onde apenas uma é a correta.

            O formato da sua resposta DEVE ser um JSON array válido, seguindo estritamente esta estrutura:
            [
                {
                    "question": "Texto da pergunta aqui...",
                    "options": ["Texto da opção A", "Texto da opção B", "Texto da opção C", "Texto da opção D", "Texto da opção E"],
                    "answer": "O texto exato da opção correta aqui..."
                }
            ]

            Não inclua nenhuma outra palavra, explicação ou formatação como \`\`\`json na sua resposta. Apenas o JSON array.

            Texto base:
            ---
            ${text.substring(0, 8000)}
            ---
        `;
        // Usamos substring para limitar o tamanho do texto e evitar exceder limites da API.

        const result = await model.generateContent(prompt);
        const response = await result.response;
        const responseText = response.text();

        // Tenta converter a resposta de texto da IA para um objeto JSON
        const generatedQuestions = JSON.parse(responseText);
        return generatedQuestions;

    } catch (error) {
        console.error("Erro ao chamar a API do Gemini ou ao fazer o parse do JSON:", error);
        // Retorna null ou um array vazio em caso de erro.
        return null;
    }
}
        if (!generatedQuestions || generatedQuestions.length === 0) {
            return res.status(500).json({ message: "A IA simulada não conseguiu gerar questões." });
        }

        // 3. Salvar o novo tema e as questões no banco de dados
        const themeResult = await db.query('INSERT INTO themes (name) VALUES ($1) RETURNING id', [themeName]);
        const newThemeId = themeResult.rows[0].id;

        for (const q of generatedQuestions) {
            await db.query(
                'INSERT INTO questions (theme_id, question, options, answer) VALUES ($1, $2, $3, $4)',
                [newThemeId, q.question, q.options, q.answer]
            );
        }

        // 4. (Opcional) Apagar o arquivo PDF do servidor após o uso
        fs.unlinkSync(file.path);

        res.status(201).json({ 
            message: `Tema '${themeName}' criado e ${generatedQuestions.length} questões foram adicionadas com sucesso.`
        });

    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Erro no servidor ao processar o arquivo.' });
    }
});

app.listen(PORT, () => {
    console.log(`Servidor rodando em http://localhost:${PORT}`);
});