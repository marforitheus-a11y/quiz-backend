// app.js - Aplicação principal modular
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { PORT, CORS_ORIGINS, NODE_ENV } = require('./config/environment');

// Importar rotas
const authRoutes = require('./routes/authRoutes');
const quizRoutes = require('./routes/quizRoutes');

const app = express();

// Middlewares de segurança
app.use(helmet());

// CORS configurado para desenvolvimento
const corsOptions = {
  origin: function (origin, callback) {
    // Permitir requests sem origin (mobile apps, curl, etc)
    if (!origin) return callback(null, true);
    
    // Permitir origins configurados
    if (CORS_ORIGINS.includes(origin)) return callback(null, true);
    
    // Permitir qualquer localhost para desenvolvimento
    if (origin && origin.includes('localhost')) return callback(null, true);
    
    return callback(new Error('Bloqueado pelo CORS'), false);
  },
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: true
};

app.use(cors(corsOptions));

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutos
  max: 100, // 100 requests por IP por janela
  message: {
    status: 'error',
    message: 'Muitas tentativas. Tente novamente em 15 minutos.'
  }
});
app.use(limiter);

// Body parsing
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));

// Logging de requests
app.use((req, res, next) => {
  const origin = req.headers.origin || 'no-origin';
  console.log(`[${new Date().toISOString()}] ${req.method} ${req.path} - Origin: ${origin}`);
  next();
});

// Health check
app.get('/health', (req, res) => {
  res.json({
    status: 'ok',
    message: 'Servidor modular funcionando!',
    timestamp: new Date().toISOString(),
    environment: NODE_ENV,
    port: PORT
  });
});

// Rotas da API
app.use('/auth', authRoutes);
app.use('/quiz', quizRoutes);

// Error handler global
app.use((error, req, res, next) => {
  console.error('Erro global:', error);
  res.status(500).json({
    status: 'error',
    message: NODE_ENV === 'production' ? 'Erro interno do servidor' : error.message
  });
});

// Iniciar servidor
const server = app.listen(PORT, () => {
  console.log('\n🚀 ===============================================');
  console.log(`📦 SERVIDOR MODULAR INICIADO`);
  console.log(`🌐 Porta: ${PORT}`);
  console.log(`🔧 Ambiente: ${NODE_ENV}`);
  console.log(`📡 Health: http://localhost:${PORT}/health`);
  console.log(`🔐 Auth: http://localhost:${PORT}/auth/*`);
  console.log(`❓ Quiz: http://localhost:${PORT}/quiz/*`);
  console.log('===============================================\n');
});

// Graceful shutdown
process.on('SIGTERM', () => {
  console.log('🛑 Recebido SIGTERM. Desligando graciosamente...');
  server.close(() => {
    console.log('✅ Servidor encerrado.');
    process.exit(0);
  });
});

process.on('SIGINT', () => {
  console.log('🛑 Recebido SIGINT. Desligando graciosamente...');
  server.close(() => {
    console.log('✅ Servidor encerrado.');
    process.exit(0);
  });
});

module.exports = app;
