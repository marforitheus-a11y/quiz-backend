const express = require('express');
const cors = require('cors');
const axios = require('axios');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const app = express();
const PORT = 4000;

// Render API URL
const RENDER_API_URL = 'https://quiz-backend-wgmc.onrender.com';

// Middleware
app.use(cors({
    origin: ['http://localhost:8080', 'http://localhost:3000'],
    credentials: true
}));
app.use(express.json());

// JWT Secret
const JWT_SECRET = 'quiz-secret-key-2024';

// Auth middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Access token required' });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ error: 'Invalid token' });
    }
    req.user = user;
    next();
  });
};

// Test connection to Render
async function testRenderConnection() {
  try {
    const response = await axios.get(`${RENDER_API_URL}/api/health`, { timeout: 10000 });
    console.log('✅ Connected to Render API');
    return true;
  } catch (error) {
    console.log('❌ Could not connect to Render API:', error.message);
    return false;
  }
}

// Routes
app.get('/api/health', async (req, res) => {
  const renderOnline = await testRenderConnection();
  res.json({
    status: 'healthy',
    render_api: renderOnline ? 'connected' : 'disconnected',
    timestamp: new Date()
  });
});

// Proxy authentication to Render
app.post('/api/auth/login', async (req, res) => {
  try {
    console.log('🔐 Proxying login to Render...');
    const response = await axios.post(`${RENDER_API_URL}/api/auth/login`, req.body, {
      timeout: 15000
    });
    
    console.log('✅ Login successful from Render');
    res.json(response.data);
  } catch (error) {
    console.error('❌ Login error:', error.message);
    if (error.response) {
      res.status(error.response.status).json(error.response.data);
    } else {
      res.status(500).json({ error: 'Connection error with Render API' });
    }
  }
});

app.post('/api/auth/signup', async (req, res) => {
  try {
    console.log('📝 Proxying signup to Render...');
    const response = await axios.post(`${RENDER_API_URL}/api/auth/signup`, req.body, {
      timeout: 15000
    });
    
    console.log('✅ Signup successful from Render');
    res.json(response.data);
  } catch (error) {
    console.error('❌ Signup error:', error.message);
    if (error.response) {
      res.status(error.response.status).json(error.response.data);
    } else {
      res.status(500).json({ error: 'Connection error with Render API' });
    }
  }
});

// Proxy quiz themes
app.get('/api/quiz/themes', async (req, res) => {
  try {
    console.log('📊 Fetching themes from Render...');
    const response = await axios.get(`${RENDER_API_URL}/api/quiz/themes`, {
      timeout: 15000
    });
    
    console.log(`✅ Got ${response.data.length} themes from Render`);
    res.json(response.data);
  } catch (error) {
    console.error('❌ Themes error:', error.message);
    if (error.response) {
      res.status(error.response.status).json(error.response.data);
    } else {
      res.status(500).json({ error: 'Connection error with Render API' });
    }
  }
});

// Proxy quiz questions
app.get('/api/quiz/themes/:themeId/questions', async (req, res) => {
  try {
    const { themeId } = req.params;
    const limit = req.query.limit || 10;
    
    console.log(`❓ Fetching questions for theme ${themeId} from Render...`);
    const response = await axios.get(`${RENDER_API_URL}/api/quiz/themes/${themeId}/questions?limit=${limit}`, {
      timeout: 15000
    });
    
    console.log(`✅ Got ${response.data.length} questions from Render`);
    res.json(response.data);
  } catch (error) {
    console.error('❌ Questions error:', error.message);
    if (error.response) {
      res.status(error.response.status).json(error.response.data);
    } else {
      res.status(500).json({ error: 'Connection error with Render API' });
    }
  }
});

// Proxy quiz submission (requires authentication)
app.post('/api/quiz/submit', authenticateToken, async (req, res) => {
  try {
    console.log('💾 Proxying quiz submission to Render...');
    const response = await axios.post(`${RENDER_API_URL}/api/quiz/submit`, req.body, {
      headers: { Authorization: req.headers.authorization },
      timeout: 15000
    });
    
    console.log('✅ Quiz submitted to Render');
    res.json(response.data);
  } catch (error) {
    console.error('❌ Submit error:', error.message);
    if (error.response) {
      res.status(error.response.status).json(error.response.data);
    } else {
      res.status(500).json({ error: 'Connection error with Render API' });
    }
  }
});

// Proxy quiz results (requires authentication)
app.get('/api/quiz/results', authenticateToken, async (req, res) => {
  try {
    console.log('📈 Fetching results from Render...');
    const response = await axios.get(`${RENDER_API_URL}/api/quiz/results`, {
      headers: { Authorization: req.headers.authorization },
      timeout: 15000
    });
    
    console.log(`✅ Got ${response.data.length} results from Render`);
    res.json(response.data);
  } catch (error) {
    console.error('❌ Results error:', error.message);
    if (error.response) {
      res.status(error.response.status).json(error.response.data);
    } else {
      res.status(500).json({ error: 'Connection error with Render API' });
    }
  }
});

// Start server
app.listen(PORT, async () => {
  console.log(`🚀 Proxy server running on http://localhost:${PORT}`);
  console.log(`🔗 Proxying to: ${RENDER_API_URL}`);
  
  // Test connection
  const connected = await testRenderConnection();
  if (connected) {
    console.log('✅ Ready to proxy requests to Render!');
  } else {
    console.log('⚠️ Render API not reachable, but server is running');
  }
});

// Handle graceful shutdown
process.on('SIGINT', () => {
  console.log('\n🔄 Shutting down proxy server...');
  process.exit(0);
});
