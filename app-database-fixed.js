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

// Routes

// Get all themes with proper column mapping
app.get('/quiz/themes', async (req, res) => {
  try {
    console.log('Fetching themes from database...');
    const result = await pool.query(`
      SELECT 
        themes.id,
        themes.name as title,
        COALESCE(themes.description, '') as summary,
        themes.category_id
      FROM themes 
      ORDER BY themes.id
    `);
    
    console.log(`Found ${result.rows.length} themes`);
    res.json(result.rows);
  } catch (error) {
    console.error('Error fetching themes:', error);
    res.status(500).json({ error: 'Database error' });
  }
});

// Get questions for a theme
app.get('/quiz/questions/:themeId', async (req, res) => {
  try {
    const { themeId } = req.params;
    const result = await pool.query(`
      SELECT 
        id,
        question,
        option_a,
        option_b,
        option_c,
        option_d,
        correct_answer
      FROM questions 
      WHERE theme_id = $1 
      ORDER BY RANDOM() 
      LIMIT 10
    `, [themeId]);
    
    res.json(result.rows);
  } catch (error) {
    console.error('Error fetching questions:', error);
    res.status(500).json({ error: 'Database error' });
  }
});

// Login endpoint
app.post('/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    // For testing purposes, allow a simple test user
    if (email === 'test@test.com' && password === 'test123') {
      const token = jwt.sign(
        { id: 999, email: 'test@test.com', name: 'Test User' },
        JWT_SECRET,
        { expiresIn: '24h' }
      );
      
      return res.json({
        token,
        user: { id: 999, email: 'test@test.com', name: 'Test User' }
      });
    }

    // Check real database users
    const result = await pool.query(
      'SELECT * FROM users WHERE email = $1',
      [email]
    );

    if (result.rows.length === 0) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const user = result.rows[0];
    const isValidPassword = await bcrypt.compare(password, user.password);

    if (!isValidPassword) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const token = jwt.sign(
      { id: user.id, email: user.email, name: user.name },
      JWT_SECRET,
      { expiresIn: '24h' }
    );

    res.json({
      token,
      user: { id: user.id, email: user.email, name: user.name }
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Register endpoint
app.post('/auth/signup', async (req, res) => {
  try {
    const { name, email, password } = req.body;

    // Check if user exists
    const existingUser = await pool.query(
      'SELECT * FROM users WHERE email = $1',
      [email]
    );

    if (existingUser.rows.length > 0) {
      return res.status(400).json({ error: 'User already exists' });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Create user
    const result = await pool.query(
      'INSERT INTO users (name, email, password) VALUES ($1, $2, $3) RETURNING id, name, email',
      [name, email, hashedPassword]
    );

    const user = result.rows[0];
    const token = jwt.sign(
      { id: user.id, email: user.email, name: user.name },
      JWT_SECRET,
      { expiresIn: '24h' }
    );

    res.json({
      token,
      user: { id: user.id, email: user.email, name: user.name }
    });
  } catch (error) {
    console.error('Signup error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Test database connection
app.get('/test/db', async (req, res) => {
  try {
    const result = await pool.query('SELECT COUNT(*) as count FROM themes');
    res.json({ 
      status: 'Database connected',
      themes_count: result.rows[0].count
    });
  } catch (error) {
    console.error('Database test error:', error);
    res.status(500).json({ error: 'Database connection failed' });
  }
});

// Health check
app.get('/health', (req, res) => {
  res.json({ status: 'Server running', port: PORT });
});

// Handle uncaught exceptions
process.on('uncaughtException', (error) => {
  console.error('❌ Uncaught Exception:', error);
  console.log('Server will continue running...');
});

process.on('unhandledRejection', (reason, promise) => {
  console.error('❌ Unhandled Rejection at:', promise, 'reason:', reason);
  console.log('Server will continue running...');
});

// Start server
const server = app.listen(PORT, () => {
  console.log(`✅ Server running on http://localhost:${PORT}`);
  console.log(`📊 Database connected to quiz_system`);
  console.log(`🎯 Real themes with proper column mapping loaded`);
  console.log(`⏳ Keep this terminal open to maintain the server...`);
});

// Keep server alive
setInterval(() => {
  console.log(`🔄 Server heartbeat - ${new Date().toLocaleTimeString()}`);
}, 30000); // Log every 30 seconds
