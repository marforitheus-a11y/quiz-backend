// =================================================================
// APP.JS PRINCIPAL - Aplicação modular COMPLETA
// =================================================================

if (process.env.NODE_ENV !== 'production') {
    require('dotenv').config();
}

// =================================================================
// IMPORTAÇÕES
// =================================================================
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const session = require('express-session');
const multer = require('multer');
const path = require('path');
const fs = require('fs');

// Configurações e utilitários
const db = require('./config/databaseFull');
const { v4: uuidv4 } = require('uuid');

// Rotas
const userRoutes = require('./routes/userRoutes');
const quizRoutes = require('./routes/quizRoutesFull');
const adminRoutes = require('./routes/adminRoutes');

// Middlewares
const authenticateToken = require('./middlewares/auth');

// Controllers
const userController = require('./controllers/userController');

// =================================================================
// VALIDAÇÃO DE AMBIENTE
// =================================================================
const JWT_SECRET = process.env.JWT_SECRET;
const GEMINI_API_KEY = process.env.GEMINI_API_KEY;

if (!JWT_SECRET) {
    console.error('❌ FATAL: JWT_SECRET não definido. Configure nas variáveis de ambiente.');
    process.exit(1);
}

if (!GEMINI_API_KEY) {
    console.warn('⚠️  AVISO: GEMINI_API_KEY não definido. Funcionalidades de IA serão limitadas.');
}

// =================================================================
// INICIALIZAÇÃO DO APP
// =================================================================
const app = express();
const PORT = process.env.PORT || 4000;

// =================================================================
// VARIÁVEIS GLOBAIS EM MEMÓRIA
// =================================================================
let activeSessions = {};
let globalMessage = null;

// =================================================================
// CONFIGURAÇÃO DE MIDDLEWARES GLOBAIS
// =================================================================

// CORS configurado para ambiente de produção e desenvolvimento
const FRONTEND_URL = process.env.FRONTEND_URL || 'http://localhost:5500,http://localhost:8080,http://localhost:3001';
const FRONTEND_URLS = FRONTEND_URL.split(',').map(s => s.trim()).filter(Boolean);

const corsOptions = {
    origin: function (origin, callback) {
        // Permitir requests sem origin (curl, server-to-server)
        if (!origin) return callback(null, true);
        
        // Permitir origins configuradas explicitamente
        if (FRONTEND_URLS.includes(origin)) return callback(null, true);
        
        // Permitir localhost em qualquer porta para desenvolvimento
        if (origin && origin.includes('localhost')) return callback(null, true);
        
        // Permitir domínios de preview/staging
        if (origin.includes('vercel.app') || origin.includes('netlify.app')) return callback(null, true);
        
        // Em desenvolvimento, permitir tudo
        if (process.env.NODE_ENV !== 'production') return callback(null, true);
        
        return callback(new Error('Não permitido pelo CORS'), false);
    },
    methods: "GET,POST,PUT,DELETE,PATCH,OPTIONS",
    allowedHeaders: ['Content-Type', 'Authorization', 'Origin', 'X-Requested-With', 'Accept'],
    credentials: true,
    optionsSuccessStatus: 200
};

app.use(cors(corsOptions));

// Headers de segurança
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            styleSrc: ["'self'", "'unsafe-inline'", "https:", "http:"],
            scriptSrc: ["'self'", "'unsafe-inline'", "'unsafe-eval'"],
            imgSrc: ["'self'", "data:", "https:", "http:"],
            connectSrc: ["'self'", "https:", "http:"],
            fontSrc: ["'self'", "https:", "http:", "data:"]
        }
    },
    crossOriginEmbedderPolicy: false
}));

// Rate limiting
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutos
    max: 1000, // limite de requests por IP
    message: {
        error: 'Muitas requisições. Tente novamente em 15 minutos.'
    },
    standardHeaders: true,
    legacyHeaders: false
});
app.use(limiter);

// Parsing de dados
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Sessões
app.use(session({
    secret: JWT_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
        secure: process.env.NODE_ENV === 'production',
        httpOnly: true,
        maxAge: 24 * 60 * 60 * 1000 // 24 horas
    }
}));

// =================================================================
// LOGGING DE REQUESTS
// =================================================================
app.use((req, res, next) => {
    try {
        const origin = req.headers.origin || req.headers.referer || '';
        const timestamp = new Date().toISOString();
        
        console.log(`[${timestamp}] ${req.method} ${req.originalUrl} - Origin: ${origin} - IP: ${req.ip}`);
        
        // Log especial para rotas de auth
        if (req.originalUrl.startsWith('/auth') || req.originalUrl.startsWith('/user')) {
            console.log(`[AUTH-REQ] ${req.method} ${req.originalUrl}`);
        }
        
        // Log especial para rotas admin
        if (req.originalUrl.startsWith('/admin')) {
            console.log(`[ADMIN-REQ] ${req.method} ${req.originalUrl}`);
        }
        
    } catch (e) {
        console.error('[REQ-LOG-ERROR]', e);
    }
    next();
});

// =================================================================
// CONFIGURAÇÃO DO MULTER (UPLOAD DE ARQUIVOS)
// =================================================================
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        const dir = './uploads';
        if (!fs.existsSync(dir)) { 
            fs.mkdirSync(dir, { recursive: true }); 
        }
        cb(null, dir);
    },
    filename: (req, file, cb) => {
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
    if (!file.mimetype) return cb(new Error('Mime type missing'), false);
    cb(null, true);
}

const upload = multer({ 
    storage: storage, 
    fileFilter, 
    limits: { fileSize: 10 * 1024 * 1024 } // 10MB
});

// =================================================================
// ROTAS PRINCIPAIS
// =================================================================

// Health check
app.get('/health', async (req, res) => {
    try {
        // Testar conexão com banco
        const dbTest = await db.testConnection();
        
        res.json({
            status: 'ok',
            message: 'Servidor modular funcionando!',
            timestamp: new Date().toISOString(),
            database: dbTest ? 'connected' : 'disconnected',
            environment: process.env.NODE_ENV || 'development',
            version: '2.0.0',
            architecture: 'modular'
        });
    } catch (error) {
        res.status(500).json({
            status: 'error',
            message: 'Erro no health check',
            timestamp: new Date().toISOString()
        });
    }
});

// =================================================================
// ROTAS DE USUÁRIO (compatibilidade com frontend existente)
// =================================================================

// Signup
app.post('/signup', userController.signup);

// Login
app.post('/login', userController.login);

// Logout
app.post('/logout', userController.logout);

// Perfil do usuário (compatibilidade)
app.get('/account/me', authenticateToken, userController.getProfile);
app.put('/account/me', authenticateToken, userController.updateProfile);

// Estatísticas
app.get('/user/stats', authenticateToken, userController.getUserStats);

// Consentimentos LGPD
app.get('/user/consents', authenticateToken, userController.getConsents);
app.put('/user/consents', authenticateToken, userController.updateConsents);

// Exportar dados
app.post('/user/export-data', authenticateToken, userController.exportUserData);

// Gestão de exclusão
app.post('/user/delete-account', authenticateToken, userController.requestAccountDeletion);
app.post('/user/cancel-deletion', authenticateToken, userController.cancelAccountDeletion);

// =================================================================
// ROTAS DO QUIZ (compatibilidade)
// =================================================================
const quizController = require('./controllers/quizControllerFull');

// Temas
app.get('/themes', authenticateToken, quizController.getThemes);

// Questões
app.post('/questions', authenticateToken, quizController.getQuestions);

// Contagens
app.post('/questions/count', authenticateToken, quizController.getQuestionsCount);
app.get('/questions/count', authenticateToken, quizController.getQuestionsCount);
app.post('/questions/counts', authenticateToken, quizController.getQuestionsCount);
app.get('/questions/counts', authenticateToken, quizController.getQuestionsCount);
app.post('/questions/counts-by-theme', authenticateToken, quizController.getCountsByTheme);
app.get('/questions/counts-by-theme', authenticateToken, quizController.getCountsByTheme);

// Finalizar quiz
app.post('/quiz/finish', authenticateToken, quizController.finishQuiz);

// Histórico
app.get('/history', authenticateToken, quizController.getHistory);
app.get('/history/:id', authenticateToken, quizController.getQuizDetails);

// Relatórios de erro
app.post('/report-error', authenticateToken, quizController.reportError);
app.post('/report-error-correct', authenticateToken, quizController.reportErrorWithCorrection);

// =================================================================
// ROTAS MODULARES
// =================================================================

// Rotas de usuário modulares
app.use('/user', userRoutes);
app.use('/auth', userRoutes);

// Rotas de quiz modulares  
app.use('/quiz', quizRoutes);

// Rotas de admin modulares
app.use('/admin', adminRoutes);

// =================================================================
// MENSAGEM GLOBAL
// =================================================================
app.get('/message', authenticateToken, (req, res) => {
    res.json({
        message: globalMessage
    });
});

// =================================================================
// ROTAS DE DEBUG E INFORMAÇÃO
// =================================================================
app.get('/debug', (req, res) => {
    res.json({
        message: 'Servidor modular funcionando!',
        timestamp: new Date().toISOString(),
        architecture: 'modular',
        version: '2.0.0',
        routes: {
            auth: ['/signup', '/login', '/logout', '/auth/*', '/user/*'],
            quiz: ['/themes', '/questions', '/quiz/*'],
            admin: ['/admin/*'],
            health: ['/health', '/debug']
        },
        database: {
            status: 'connected',
            ssl: process.env.DB_FORCE_SSL === 'true'
        },
        environment: process.env.NODE_ENV || 'development'
    });
});

app.get('/api/info', (req, res) => {
    res.json({
        name: 'Quiz Backend Modular',
        version: '2.0.0',
        architecture: 'MVC Modular',
        features: [
            'Autenticação JWT',
            'LGPD Compliance',
            'Sistema de Quiz Completo',
            'Painel Administrativo',
            'Relatórios de Erro',
            'Upload de Arquivos',
            'Rate Limiting',
            'CORS Configurado'
        ],
        endpoints: {
            total: 25,
            auth: 8,
            quiz: 12,
            admin: 15
        }
    });
});

// =================================================================
// MIDDLEWARE DE ERRO GLOBAL
// =================================================================
app.use((error, req, res, next) => {
    console.error('❌ Erro não tratado:', error);
    
    // Erro do Multer
    if (error instanceof multer.MulterError) {
        if (error.code === 'LIMIT_FILE_SIZE') {
            return res.status(413).json({ 
                error: 'Arquivo muito grande. Limite: 10MB' 
            });
        }
    }
    
    // Erro de arquivo não permitido
    if (error.message === 'Tipo de arquivo não permitido') {
        return res.status(400).json({ 
            error: 'Tipo de arquivo não permitido. Use: PDF, PNG, JPG, JPEG, GIF' 
        });
    }
    
    // Erro genérico
    res.status(500).json({
        error: 'Erro interno do servidor',
        timestamp: new Date().toISOString(),
        message: process.env.NODE_ENV === 'development' ? error.message : 'Erro interno'
    });
});

// =================================================================
// MIDDLEWARE 404
// =================================================================
app.use((req, res) => {
    res.status(404).json({
        error: 'Rota não encontrada',
        method: req.method,
        path: req.originalUrl,
        timestamp: new Date().toISOString(),
        available_routes: [
            'GET /health',
            'GET /debug',
            'POST /signup',
            'POST /login',
            'GET /themes',
            'POST /questions',
            'GET /admin/*',
            'GET /user/*',
            'GET /quiz/*'
        ]
    });
});

// =================================================================
// INICIALIZAÇÃO DO SERVIDOR
// =================================================================
async function startServer() {
    try {
        console.log('🚀 Iniciando servidor modular...');
        
        // Inicializar banco de dados
        await db.initialize();
        
        // Iniciar servidor
        const server = app.listen(PORT, () => {
            console.log('\n🎯 ===============================================');
            console.log('🚀 SERVIDOR MODULAR INICIADO COM SUCESSO!');
            console.log(`📡 Porta: ${PORT}`);
            console.log(`🏗️  Arquitetura: MVC Modular`);
            console.log(`🌍 Ambiente: ${process.env.NODE_ENV || 'development'}`);
            console.log(`🗄️  Banco: PostgreSQL (SSL: ${process.env.DB_FORCE_SSL === 'true'})`);
            console.log('📋 Endpoints principais:');
            console.log('   GET  /health');
            console.log('   GET  /debug');
            console.log('   POST /signup');
            console.log('   POST /login');
            console.log('   GET  /themes');
            console.log('   POST /questions');
            console.log('   GET  /admin/dashboard/metrics');
            console.log('   GET  /user/stats');
            console.log('===============================================\n');
        });

        // Graceful shutdown
        process.on('SIGTERM', async () => {
            console.log('\n🛑 Recebido SIGTERM, fechando servidor...');
            server.close(async () => {
                await db.closePool();
                console.log('✅ Servidor fechado graciosamente');
                process.exit(0);
            });
        });

        process.on('SIGINT', async () => {
            console.log('\n🛑 Recebido SIGINT, fechando servidor...');
            server.close(async () => {
                await db.closePool();
                console.log('✅ Servidor fechado graciosamente');
                process.exit(0);
            });
        });

    } catch (error) {
        console.error('❌ Erro ao iniciar servidor:', error);
        process.exit(1);
    }
}

// Iniciar servidor
startServer();

module.exports = app;
