// =================================================================
// APP.JS SIMPLIFICADO - Para teste da arquitetura modular
// =================================================================

if (process.env.NODE_ENV !== 'production') {
    require('dotenv').config();
}

const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');

// Controllers
const userController = require('./controllers/userController');
const quizController = require('./controllers/quizControllerFull');

// Middlewares
const authenticateToken = require('./middlewares/auth');

// =================================================================
// INICIALIZAÇÃO DO APP
// =================================================================
const app = express();
const PORT = process.env.PORT || 4000;

// =================================================================
// MIDDLEWARES BÁSICOS
// =================================================================
app.use(cors({
    origin: true,
    credentials: true
}));

app.use(helmet({
    contentSecurityPolicy: false
}));

app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));

// Rate limiting simples
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 1000
});
app.use(limiter);

// =================================================================
// LOGGING
// =================================================================
app.use((req, res, next) => {
    console.log(`[${new Date().toISOString()}] ${req.method} ${req.originalUrl}`);
    next();
});

// =================================================================
// ROTAS PRINCIPAIS
// =================================================================

// Health check (sem banco)
app.get('/health', (req, res) => {
    res.json({
        status: 'ok',
        message: 'Servidor modular funcionando!',
        timestamp: new Date().toISOString(),
        environment: process.env.NODE_ENV || 'development',
        version: '2.0.0',
        architecture: 'modular'
    });
});

// Debug info
app.get('/debug', (req, res) => {
    res.json({
        message: 'Servidor modular funcionando!',
        timestamp: new Date().toISOString(),
        architecture: 'modular',
        version: '2.0.0',
        database_url: process.env.DATABASE_URL ? 'configured' : 'not configured',
        jwt_secret: process.env.JWT_SECRET ? 'configured' : 'not configured',
        gemini_key: process.env.GEMINI_API_KEY ? 'configured' : 'not configured',
        environment: process.env.NODE_ENV || 'development'
    });
});

// =================================================================
// ROTAS DE AUTENTICAÇÃO (com proteção de erro)
// =================================================================
app.post('/signup', async (req, res) => {
    try {
        await userController.signup(req, res);
    } catch (error) {
        console.error('❌ Erro no signup:', error);
        res.status(500).json({ error: 'Erro interno do servidor' });
    }
});

app.post('/login', async (req, res) => {
    try {
        await userController.login(req, res);
    } catch (error) {
        console.error('❌ Erro no login:', error);
        res.status(500).json({ error: 'Erro interno do servidor' });
    }
});

app.post('/logout', userController.logout);

// =================================================================
// ROTAS PROTEGIDAS (com proteção de erro)
// =================================================================
app.get('/account/me', authenticateToken, async (req, res) => {
    try {
        await userController.getProfile(req, res);
    } catch (error) {
        console.error('❌ Erro no perfil:', error);
        res.status(500).json({ error: 'Erro interno do servidor' });
    }
});

app.get('/user/stats', authenticateToken, async (req, res) => {
    try {
        await userController.getUserStats(req, res);
    } catch (error) {
        console.error('❌ Erro nas estatísticas:', error);
        res.status(500).json({ error: 'Erro interno do servidor' });
    }
});

app.get('/themes', authenticateToken, async (req, res) => {
    try {
        await quizController.getThemes(req, res);
    } catch (error) {
        console.error('❌ Erro nos temas:', error);
        res.status(500).json({ error: 'Erro interno do servidor' });
    }
});

app.post('/questions', authenticateToken, async (req, res) => {
    try {
        await quizController.getQuestions(req, res);
    } catch (error) {
        console.error('❌ Erro nas questões:', error);
        res.status(500).json({ error: 'Erro interno do servidor' });
    }
});

// =================================================================
// TESTE DE BANCO
// =================================================================
app.get('/test-db', async (req, res) => {
    try {
        const db = require('./config/databaseFull');
        const isConnected = await db.testConnection();
        res.json({
            database_connected: isConnected,
            database_url: process.env.DATABASE_URL ? 'configured' : 'not configured',
            ssl_enabled: process.env.DB_FORCE_SSL === 'true'
        });
    } catch (error) {
        res.json({
            database_connected: false,
            error: error.message,
            database_url: process.env.DATABASE_URL ? 'configured' : 'not configured'
        });
    }
});

// =================================================================
// MIDDLEWARE DE ERRO
// =================================================================
app.use((error, req, res, next) => {
    console.error('❌ Erro não tratado:', error);
    res.status(500).json({
        error: 'Erro interno do servidor',
        timestamp: new Date().toISOString()
    });
});

// 404
app.use((req, res) => {
    res.status(404).json({
        error: 'Rota não encontrada',
        method: req.method,
        path: req.originalUrl,
        timestamp: new Date().toISOString()
    });
});

// =================================================================
// INICIALIZAÇÃO DO SERVIDOR
// =================================================================
async function startServer() {
    try {
        console.log('🚀 Iniciando servidor modular simplificado...');
        
        const server = app.listen(PORT, () => {
            console.log('\n🎯 ===============================================');
            console.log('🚀 SERVIDOR MODULAR INICIADO COM SUCESSO!');
            console.log(`📡 Porta: ${PORT}`);
            console.log(`🏗️  Arquitetura: MVC Modular (Simplificado)`);
            console.log(`🌍 Ambiente: ${process.env.NODE_ENV || 'development'}`);
            console.log('📋 Endpoints disponíveis:');
            console.log('   GET  /health');
            console.log('   GET  /debug');
            console.log('   GET  /test-db');
            console.log('   POST /signup');
            console.log('   POST /login');
            console.log('   GET  /account/me (com auth)');
            console.log('   GET  /themes (com auth)');
            console.log('   POST /questions (com auth)');
            console.log('===============================================\n');
        });

        // Graceful shutdown
        process.on('SIGTERM', () => {
            console.log('\n🛑 Recebido SIGTERM, fechando servidor...');
            server.close(() => {
                console.log('✅ Servidor fechado graciosamente');
                process.exit(0);
            });
        });

        process.on('SIGINT', () => {
            console.log('\n🛑 Recebido SIGINT, fechando servidor...');
            server.close(() => {
                console.log('✅ Servidor fechado graciosamente');
                process.exit(0);
            });
        });

    } catch (error) {
        console.error('❌ Erro ao iniciar servidor:', error);
        process.exit(1);
    }
}

startServer();

module.exports = app;
