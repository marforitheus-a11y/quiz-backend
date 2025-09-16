const express = require('express');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const fs = require('fs');
const path = require('path');

const app = express();
const PORT = 4000;

// Load database from JSON file
let db;
try {
  const dbPath = path.join(__dirname, 'db.json');
  db = JSON.parse(fs.readFileSync(dbPath, 'utf8'));
  console.log('✅ Database loaded from db.json');
  console.log(`📊 ${db.themes.length} themes loaded`);
  console.log(`❓ ${db.questions.length} questions loaded`);
} catch (error) {
  console.error('❌ Error loading database:', error);
  process.exit(1);
}

// Middleware
app.use(cors());
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

// Memory storage for quiz results
const quizResults = new Map();

// Routes
app.get('/api/health', (req, res) => {
  res.json({
    status: 'healthy',
    database: 'json_file',
    themes: db.themes.length,
    questions: db.questions.length,
    timestamp: new Date()
  });
});

// Authentication routes
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    
    // Find user by email (username in JSON)
    const user = db.users.find(u => u.username === email);
    if (!user) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // Check password
    let isValidPassword = false;
    if (user.password.startsWith('$2b$')) {
      // Hashed password
      isValidPassword = await bcrypt.compare(password, user.password);
    } else {
      // Plain text password
      isValidPassword = password === user.password;
    }

    if (!isValidPassword) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // Generate token
    const token = jwt.sign(
      { 
        id: user.id, 
        email: user.username, 
        name: user.username,
        isAdmin: user.role === 'admin'
      },
      JWT_SECRET,
      { expiresIn: '24h' }
    );

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
    console.error('Login error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Quiz routes
app.get('/api/quiz/themes', (req, res) => {
  try {
    // Convert themes to expected format
    const themes = db.themes.map(theme => ({
      id: theme.id,
      title: theme.name,
      summary: theme.name,
      category_id: 1,
      category_name: "Quiz",
      question_count: db.questions.filter(q => q.themeId === theme.id).length
    }));
    
    res.json(themes);
  } catch (error) {
    console.error('Error fetching themes:', error);
    res.status(500).json({ error: 'Error fetching themes' });
  }
});

app.get('/api/quiz/themes/:themeId/questions', (req, res) => {
  try {
    const themeId = parseInt(req.params.themeId);
    const limit = parseInt(req.query.limit) || 10;
    
    // Get questions for theme
    const themeQuestions = db.questions.filter(q => q.themeId === themeId).slice(0, limit);
    
    // Convert to expected format
    const questions = themeQuestions.map((q, index) => ({
      id: themeId * 1000 + index + 1,
      text: q.question,
      option_a: q.options[0],
      option_b: q.options[1], 
      option_c: q.options[2],
      option_d: q.options[3],
      correct_answer: ['A', 'B', 'C', 'D'][q.options.indexOf(q.answer)],
      difficulty: 'medium',
      explanation: ''
    }));
    
    res.json(questions);
  } catch (error) {
    console.error('Error fetching questions:', error);
    res.status(500).json({ error: 'Error fetching questions' });
  }
});

// Quiz submission
app.post('/api/quiz/submit', authenticateToken, (req, res) => {
  try {
    const { themeId, answers, score, totalQuestions } = req.body;
    const userId = req.user.id;

    const result = {
      id: Date.now(),
      user_id: userId,
      theme_id: themeId,
      score,
      total_questions: totalQuestions,
      answers,
      completed_at: new Date()
    };

    if (!quizResults.has(userId)) {
      quizResults.set(userId, []);
    }
    quizResults.get(userId).push(result);

    res.json({
      success: true,
      resultId: result.id,
      score,
      percentage: Math.round((score / totalQuestions) * 100)
    });
  } catch (error) {
    console.error('Error submitting quiz:', error);
    res.status(500).json({ error: 'Error submitting quiz' });
  }
});

// Get quiz results
app.get('/api/quiz/results', authenticateToken, (req, res) => {
  try {
    const userId = req.user.id;
    const userResults = quizResults.get(userId) || [];
    
    const formattedResults = userResults.map(result => {
      const theme = db.themes.find(t => t.id == result.theme_id);
      return {
        id: result.id,
        score: result.score,
        total_questions: result.total_questions,
        completed_at: result.completed_at,
        theme_name: theme ? theme.name : 'Tema não encontrado',
        percentage: Math.round((result.score / result.total_questions) * 100)
      };
    });

    res.json(formattedResults);
  } catch (error) {
    console.error('Error fetching results:', error);
    res.status(500).json({ error: 'Error fetching results' });
  }
});

// Start server
app.listen(PORT, () => {
  console.log(`🚀 Server running on http://localhost:${PORT}`);
  console.log(`📊 Database: ${db.themes.length} themes, ${db.questions.length} questions`);
  console.log('✅ Using REAL data from db.json');
  console.log('⚡ Ready to use!');
});

// Handle graceful shutdown
process.on('SIGINT', () => {
  console.log('\n🔄 Shutting down server...');
  process.exit(0);
});
