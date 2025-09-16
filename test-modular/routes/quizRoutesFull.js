// =================================================================
// QUIZ ROUTES - Rotas completas do sistema de quiz
// =================================================================

const express = require('express');
const router = express.Router();
const quizController = require('../controllers/quizControllerFull');
const authenticateToken = require('../middlewares/auth');

// =================================================================
// ROTAS DO QUIZ (todas protegidas)
// =================================================================

// Temas disponíveis
router.get('/themes', authenticateToken, quizController.getThemes);

// Questões para quiz
router.post('/questions', authenticateToken, quizController.getQuestions);

// Contagem de questões
router.post('/questions/count', authenticateToken, quizController.getQuestionsCount);
router.get('/questions/count', authenticateToken, quizController.getQuestionsCount);
router.post('/questions/counts', authenticateToken, quizController.getQuestionsCount);
router.get('/questions/counts', authenticateToken, quizController.getQuestionsCount);

// Contagem por tema
router.post('/questions/counts-by-theme', authenticateToken, quizController.getCountsByTheme);
router.get('/questions/counts-by-theme', authenticateToken, quizController.getCountsByTheme);

// Finalizar quiz
router.post('/finish', authenticateToken, quizController.finishQuiz);

// =================================================================
// HISTÓRICO E RESULTADOS
// =================================================================

// Histórico de quizzes
router.get('/history', authenticateToken, quizController.getHistory);

// Detalhes de um quiz específico
router.get('/history/:id', authenticateToken, quizController.getQuizDetails);

// =================================================================
// RELATÓRIOS DE ERRO
// =================================================================

// Reportar erro em questão
router.post('/report-error', authenticateToken, quizController.reportError);

// Reportar erro com correção sugerida
router.post('/report-error-correct', authenticateToken, quizController.reportErrorWithCorrection);

// =================================================================
// ROTAS DE DEBUG
// =================================================================
router.get('/debug', (req, res) => {
    res.json({
        message: 'Quiz routes funcionando!',
        timestamp: new Date().toISOString(),
        routes: [
            'GET /quiz/themes',
            'POST /quiz/questions',
            'GET|POST /quiz/questions/count',
            'GET|POST /quiz/questions/counts',
            'GET|POST /quiz/questions/counts-by-theme',
            'POST /quiz/finish',
            'GET /quiz/history',
            'GET /quiz/history/:id',
            'POST /quiz/report-error',
            'POST /quiz/report-error-correct'
        ]
    });
});

module.exports = router;
