const express = require('express');
const cors = require('cors');
const axios = require('axios');

const app = express();
const PORT = 4000;

// URL da API do Render com dados reais
const RENDER_API_URL = 'https://quiz-api-z4ri.onrender.com';

// Middleware
app.use(cors());
app.use(express.json());

// Proxy para API do Render
app.get('/api/health', (req, res) => {
  res.json({
    status: 'healthy',
    mode: 'proxy_to_render',
    render_api: RENDER_API_URL,
    timestamp: new Date()
  });
});

// Auth routes - proxy para Render
app.post('/api/auth/login', async (req, res) => {
  try {
    const response = await axios.post(`${RENDER_API_URL}/login`, req.body);
    res.json(response.data);
  } catch (error) {
    console.error('Login error:', error.response?.data || error.message);
    res.status(error.response?.status || 500).json({ 
      error: error.response?.data?.error || 'Erro no login' 
    });
  }
});

// Quiz routes - proxy para Render
app.get('/api/quiz/themes', async (req, res) => {
  try {
    const response = await axios.get(`${RENDER_API_URL}/categories`);
    
    // Converter formato de categories para themes
    const themes = response.data.map(category => ({
      id: category.id,
      title: category.name,
      summary: category.description || category.name,
      category_id: category.id,
      category_name: category.name,
      question_count: category.questionCount || 0
    }));
    
    console.log(`✅ ${themes.length} themes loaded from Render`);
    res.json(themes);
  } catch (error) {
    console.error('Error fetching themes:', error.response?.data || error.message);
    res.status(error.response?.status || 500).json({ 
      error: 'Erro ao buscar temas' 
    });
  }
});

app.get('/api/quiz/themes/:themeId/questions', async (req, res) => {
  try {
    const { themeId } = req.params;
    const limit = req.query.limit || 10;
    
    const response = await axios.get(`${RENDER_API_URL}/questions`, {
      params: { 
        category: themeId, 
        limit: limit 
      }
    });
    
    console.log(`✅ ${response.data.length} questions loaded for theme ${themeId}`);
    res.json(response.data);
  } catch (error) {
    console.error('Error fetching questions:', error.response?.data || error.message);
    res.status(error.response?.status || 500).json({ 
      error: 'Erro ao buscar questões' 
    });
  }
});

// Quiz submission
app.post('/api/quiz/submit', async (req, res) => {
  try {
    // Para submissão, vamos simular sucesso localmente
    // já que não temos token válido para o Render
    const { themeId, answers, score, totalQuestions } = req.body;
    
    res.json({
      success: true,
      resultId: Date.now(),
      score,
      percentage: Math.round((score / totalQuestions) * 100)
    });
  } catch (error) {
    console.error('Error submitting quiz:', error);
    res.status(500).json({ error: 'Erro ao submeter quiz' });
  }
});

// Quiz results
app.get('/api/quiz/results', (req, res) => {
  // Retorna resultados simulados já que não temos autenticação com Render
  res.json([]);
});

// Start server
app.listen(PORT, () => {
  console.log(`🚀 Proxy server running on http://localhost:${PORT}`);
  console.log(`🔗 Proxying to: ${RENDER_API_URL}`);
  console.log('✅ Using REAL data from Render production API');
  console.log('⚡ Ready to test with real 69 themes!');
});

// Handle graceful shutdown
process.on('SIGINT', () => {
  console.log('\n🔄 Shutting down proxy server...');
  process.exit(0);
});
