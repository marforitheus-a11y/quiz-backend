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
const JWT_SECRET = 'quiz-secret-key-2024';

// Mock user for testing
const users = new Map();
users.set('admin', { id: 1, username: 'admin', password: 'admin123', role: 'admin' });
users.set('test@test.com', { id: 2, username: 'test@test.com', password: 'test123', role: 'user' });

// Mock data com os dados reais do Render
const realThemes = [
  { id: 1, title: "Administração Pública", summary: "Conceitos básicos de administração pública", category_id: 1, category_name: "Direito", question_count: 25 },
  { id: 2, title: "Direito Constitucional", summary: "Princípios e normas constitucionais", category_id: 1, category_name: "Direito", question_count: 30 },
  { id: 3, title: "Direito Administrativo", summary: "Atos e processos administrativos", category_id: 1, category_name: "Direito", question_count: 22 },
  { id: 4, title: "Direito Penal", summary: "Crimes e suas punições", category_id: 1, category_name: "Direito", question_count: 18 },
  { id: 5, title: "Direito Processual Penal", summary: "Procedimentos penais", category_id: 1, category_name: "Direito", question_count: 15 },
  { id: 6, title: "Matemática", summary: "Conceitos matemáticos fundamentais", category_id: 2, category_name: "Exatas", question_count: 40 },
  { id: 7, title: "Português", summary: "Gramática e interpretação", category_id: 3, category_name: "Línguas", question_count: 35 },
  { id: 8, title: "Informática", summary: "Conhecimentos básicos de informática", category_id: 4, category_name: "Tecnologia", question_count: 20 },
  { id: 9, title: "História do Brasil", summary: "História do Brasil", category_id: 5, category_name: "Humanas", question_count: 15 },
  { id: 10, title: "Geografia", summary: "Geografia do Brasil e Geral", category_id: 5, category_name: "Humanas", question_count: 18 }
];

const mockQuestions = [
  {
    id: 1, text: "Qual é o princípio fundamental da administração pública?",
    option_a: "Eficiência", option_b: "Legalidade", option_c: "Moralidade", option_d: "Publicidade",
    correct_answer: "B", difficulty: "medium"
  },
  {
    id: 2, text: "O que caracteriza um ato administrativo?",
    option_a: "Presunção de legitimidade", option_b: "Imperatividade", option_c: "Autoexecutoriedade", option_d: "Todas as anteriores",
    correct_answer: "D", difficulty: "medium"
  },
  {
    id: 3, text: "Qual dos direitos fundamentais é considerado absoluto?",
    option_a: "Direito à vida", option_b: "Direito à propriedade", option_c: "Nenhum direito é absoluto", option_d: "Direito à liberdade",
    correct_answer: "C", difficulty: "hard"
  }
];

const results = new Map();

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
  res.json({ 
    status: 'healthy', 
    themes: realThemes.length, 
    timestamp: new Date(),
    message: 'Server funcionando com dados simulados (baseados no Render)'
  });
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    console.log(`🔐 Login attempt: ${email}`);
    
    const user = users.get(email);
    if (!user || password !== user.password) {
      return res.status(401).json({ error: 'Credenciais inválidas' });
    }
    
    const token = jwt.sign({ 
      id: user.id, 
      email: user.username, 
      name: user.username, 
      isAdmin: user.role === 'admin' 
    }, JWT_SECRET, { expiresIn: '24h' });
    
    console.log('✅ Login successful');
    res.json({ 
      token, 
      user: { 
        id: user.id, 
        email: user.username, 
        name: user.username, 
        isAdmin: user.role === 'admin' 
      } 
    });
  } catch (error) {
    console.error('❌ Login error:', error);
    res.status(500).json({ error: 'Erro interno' });
  }
});

app.get('/api/quiz/themes', (req, res) => {
  console.log(`📊 Returning ${realThemes.length} themes`);
  res.json(realThemes);
});

app.get('/api/quiz/themes/:id/questions', (req, res) => {
  const limit = parseInt(req.query.limit) || 10;
  console.log(`❓ Returning questions for theme ${req.params.id}`);
  res.json(mockQuestions.slice(0, limit));
});

app.post('/api/quiz/submit', auth, (req, res) => {
  const { themeId, answers, score, totalQuestions } = req.body;
  const result = {
    id: Date.now(),
    user_id: req.user.id,
    theme_id: themeId,
    score, total_questions: totalQuestions,
    completed_at: new Date()
  };
  
  if (!results.has(req.user.id)) results.set(req.user.id, []);
  results.get(req.user.id).push(result);
  
  console.log(`💾 Quiz submitted: ${score}/${totalQuestions}`);
  res.json({ success: true, resultId: result.id, score, percentage: Math.round((score/totalQuestions)*100) });
});

app.get('/api/quiz/results', auth, (req, res) => {
  const userResults = results.get(req.user.id) || [];
  const formatted = userResults.map(r => ({
    id: r.id, score: r.score, total_questions: r.total_questions,
    completed_at: r.completed_at,
    theme_name: realThemes.find(t => t.id == r.theme_id)?.title || 'Tema',
    percentage: Math.round((r.score/r.total_questions)*100)
  }));
  
  console.log(`📈 Returning ${formatted.length} results`);
  res.json(formatted);
});

const server = app.listen(PORT, () => {
  console.log(`🚀 Server FUNCIONANDO em http://localhost:${PORT}`);
  console.log(`📊 ${realThemes.length} temas disponíveis`);
  console.log(`✅ Login: admin/admin123 ou test@test.com/test123`);
  console.log('⚡ PRONTO PARA USAR!');
});

// Não deixa o servidor morrer
server.on('error', (err) => {
  console.error('Server error:', err);
});

process.on('uncaughtException', (err) => {
  console.error('Uncaught exception:', err);
});

process.on('unhandledRejection', (err) => {
  console.error('Unhandled rejection:', err);
});
