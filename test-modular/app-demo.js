// app-demo.js - Versão de demonstração sem banco
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');

const app = express();
const PORT = 4001;

// Middlewares
app.use(helmet());
app.use(cors({
  origin: ['http://localhost:8080', 'http://localhost:3000', 'http://127.0.0.1:8080'],
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: true
}));
app.use(express.json());

// Logging
app.use((req, res, next) => {
  console.log(`[${new Date().toISOString()}] ${req.method} ${req.path}`);
  next();
});

// Health check
app.get('/health', (req, res) => {
  res.json({
    status: 'ok',
    message: 'Servidor modular DEMO funcionando!',
    timestamp: new Date().toISOString(),
    port: PORT,
    architecture: 'Modular MVC',
    improvements: [
      'Arquitetura MVC limpa',
      'CORS configurado corretamente',
      'Middlewares organizados',
      'Código legível e manutenível'
    ]
  });
});

// Demo auth endpoints
app.post('/auth/login', (req, res) => {
  const { loginIdentifier, password } = req.body;
  
  // Demo: aceitar brunaamor/123456
  if (loginIdentifier === 'brunaamor' && password === '123456') {
    res.json({
      status: 'success',
      message: 'Login bem-sucedido! (DEMO)',
      token: 'demo-jwt-token-here',
      user: {
        id: 1,
        username: 'brunaamor',
        email: 'brunaamor@demo.com',
        role: 'user'
      }
    });
  } else {
    res.status(401).json({
      status: 'error',
      message: 'Credenciais inválidas. Use: brunaamor/123456'
    });
  }
});

app.get('/auth/me', (req, res) => {
  res.json({
    status: 'success',
    message: 'Endpoint protegido funcionando! (DEMO)',
    user: { username: 'brunaamor', role: 'user' }
  });
});

// Demo quiz endpoints
app.get('/quiz/themes', (req, res) => {
  res.json({
    status: 'success',
    themes: [
      { id: 1, name: 'JavaScript', category_name: 'Programação' },
      { id: 2, name: 'React', category_name: 'Frontend' },
      { id: 3, name: 'Node.js', category_name: 'Backend' }
    ]
  });
});

app.get('/quiz/questions', (req, res) => {
  res.json({
    status: 'success',
    questions: [
      {
        id: 1,
        question_text: 'O que é JavaScript?',
        answer_a: 'Uma linguagem de programação',
        answer_b: 'Um framework',
        answer_c: 'Uma biblioteca',
        answer_d: 'Um banco de dados',
        correct_answer: 'a',
        theme_name: 'JavaScript'
      }
    ]
  });
});

// Iniciar servidor
app.listen(PORT, () => {
  console.log('\n🎯 ===============================================');
  console.log('🚀 SERVIDOR MODULAR DEMO INICIADO');
  console.log(`📡 Porta: ${PORT}`);
  console.log('✨ Demonstração da arquitetura otimizada');
  console.log('📋 Endpoints disponíveis:');
  console.log('   GET  /health');
  console.log('   POST /auth/login (brunaamor/123456)');
  console.log('   GET  /auth/me');
  console.log('   GET  /quiz/themes');
  console.log('   GET  /quiz/questions');
  console.log('===============================================\n');
});

module.exports = app;
