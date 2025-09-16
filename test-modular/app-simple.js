// app-simple.js - Servidor simples para teste
const express = require('express');
const cors = require('cors');

const app = express();
const PORT = 4000;

// Middlewares básicos
app.use(cors());
app.use(express.json());

// Logging
app.use((req, res, next) => {
  console.log(`${req.method} ${req.path}`);
  next();
});

// Health check
app.get('/health', (req, res) => {
  res.json({
    status: 'ok',
    message: 'Servidor simples funcionando!',
    timestamp: new Date().toISOString(),
    architecture: 'simple-test'
  });
});

// Debug endpoint
app.get('/debug', (req, res) => {
  res.json({
    message: 'Servidor simples funcionando!',
    timestamp: new Date().toISOString(),
    architecture: 'simple-test',
    themes_available: [
      'Código de Posturas (Guarujá)',
      'Direito Constitucional', 
      'Direito Administrativo'
    ],
    routes: [
      'GET /health',
      'GET /debug',
      'POST /auth/signup',
      'POST /auth/login',
      'GET /quiz/themes',
      'GET /quiz/questions?theme=X&count=Y'
    ]
  });
});

// Rota de cadastro simples
app.post('/auth/signup', (req, res) => {
  console.log('Cadastro recebido:', req.body);
  const { username, email, password, name } = req.body;
  
  if (!username || !email || !password) {
    return res.status(400).json({
      success: false,
      message: 'Campos obrigatórios: username, email, password'
    });
  }
  
  // Simular cadastro bem-sucedido
  res.json({
    success: true,
    message: 'Usuário criado com sucesso!',
    user: {
      id: 1,
      username,
      email,
      name: name || username
    }
  });
});

// Rota de login simples
app.post('/auth/login', (req, res) => {
  console.log('Login recebido:', req.body);
  const { loginIdentifier, password } = req.body;
  
  if (!loginIdentifier || !password) {
    return res.status(400).json({
      success: false,
      message: 'Login e senha são obrigatórios'
    });
  }
  
  // Simular login bem-sucedido
  res.json({
    success: true,
    message: 'Login realizado com sucesso!',
    token: 'fake-jwt-token-for-testing',
    user: {
      id: 1,
      username: loginIdentifier,
      email: `${loginIdentifier}@teste.com`
    }
  });
});

// Rota de temas simples (com dados reais)
app.get('/quiz/themes', (req, res) => {
  console.log('Temas solicitados');
  res.json({
    themes: [
      'Código de Posturas (Guarujá)',
      'Direito Constitucional',
      'Direito Administrativo'
    ]
  });
});

// Rota de questões simples (com dados mais realistas)
app.get('/quiz/questions', (req, res) => {
  const { theme, count = 5 } = req.query;
  console.log(`Questões solicitadas: ${theme}, count: ${count}`);
  
  // Questões baseadas nos temas reais
  const questionTemplates = {
    'Código de Posturas (Guarujá)': [
      {
        question: 'De acordo com a Lei Complementar nº 44/1998 de Guarujá, a quem compete zelar pela manutenção da Cidade?',
        options: ['Aos moradores', 'À Prefeitura', 'Ao Governo do Estado', 'Às empresas privadas'],
        correct: 1
      },
      {
        question: 'Segundo o Código de Posturas de Guarujá, qual é a penalidade para estabelecimentos que não cumprem as normas de funcionamento?',
        options: ['Advertência', 'Multa', 'Interdição', 'Todas as anteriores'],
        correct: 3
      }
    ],
    'Direito Constitucional': [
      {
        question: 'Qual dos seguintes não é um fundamento da República Federativa do Brasil, segundo a Constituição?',
        options: ['A soberania', 'A cidadania', 'O pluralismo político', 'A garantia do desenvolvimento nacional'],
        correct: 3
      },
      {
        question: 'Segundo a Constituição Federal, quais são os Poderes da União?',
        options: ['Executivo e Legislativo', 'Legislativo, Executivo e Judiciário', 'Judiciário e Executivo', 'Federal, Estadual e Municipal'],
        correct: 1
      }
    ],
    'Direito Administrativo': [
      {
        question: 'Qual princípio NÃO está expresso no Art. 37 da CF?',
        options: ['Legalidade', 'Impessoalidade', 'Moralidade', 'Razoabilidade'],
        correct: 3
      },
      {
        question: 'O ato administrativo que possui vício de legalidade é considerado:',
        options: ['Válido', 'Anulável', 'Nulo', 'Inexistente'],
        correct: 2
      }
    ]
  };
  
  const questions = [];
  const templates = questionTemplates[theme] || questionTemplates['Direito Constitucional'];
  
  for (let i = 1; i <= count; i++) {
    const templateIndex = (i - 1) % templates.length;
    const template = templates[templateIndex];
    
    questions.push({
      id: i,
      question: template.question,
      options: template.options,
      correct: template.correct
    });
  }
  
  res.json(questions);
});

// Error handler
app.use((err, req, res, next) => {
  console.error('Erro:', err);
  res.status(500).json({
    success: false,
    message: 'Erro interno do servidor'
  });
});

// 404 handler
app.use((req, res) => {
  console.log(`Rota não encontrada: ${req.method} ${req.path}`);
  res.status(404).json({
    success: false,
    message: `Rota não encontrada: ${req.method} ${req.path}`
  });
});

// Iniciar servidor
app.listen(PORT, () => {
  console.log('\n🚀 ===============================================');
  console.log(`📦 SERVIDOR SIMPLES INICIADO`);
  console.log(`🌐 Porta: ${PORT}`);
  console.log(`📡 Health: http://localhost:${PORT}/health`);
  console.log(`🔐 Auth: http://localhost:${PORT}/auth/*`);
  console.log(`❓ Quiz: http://localhost:${PORT}/quiz/*`);
  console.log('===============================================\n');
});

module.exports = app;
