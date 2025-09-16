// routes/quizRoutes.js - Rotas do quiz
const express = require('express');
const router = express.Router();
const QuizController = require('../controllers/quizController');
const { authenticateToken } = require('../middlewares/auth');

// Rotas do quiz (todas protegidas)
router.get('/themes', authenticateToken, QuizController.getThemes);
router.get('/questions', authenticateToken, QuizController.getQuestions);
router.get('/user-stats', authenticateToken, QuizController.getUserStats);
router.post('/submit', authenticateToken, QuizController.submitQuiz);

module.exports = router;
