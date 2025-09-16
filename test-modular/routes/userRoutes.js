// =================================================================
// AUTH ROUTES - Rotas de autenticação e usuários COMPLETAS
// =================================================================

const express = require('express');
const router = express.Router();
const userController = require('../controllers/userController');
const authenticateToken = require('../middlewares/auth');

// =================================================================
// ROTAS PÚBLICAS (sem autenticação)
// =================================================================

// Registro de usuário
router.post('/signup', userController.signup);

// Login
router.post('/login', userController.login);

// Logout (pode ser público)
router.post('/logout', userController.logout);

// =================================================================
// ROTAS PROTEGIDAS (com autenticação)
// =================================================================

// Perfil do usuário
router.get('/me', authenticateToken, userController.getProfile);
router.put('/me', authenticateToken, userController.updateProfile);

// Estatísticas do usuário
router.get('/stats', authenticateToken, userController.getUserStats);

// =================================================================
// ROTAS LGPD - Gestão de dados pessoais
// =================================================================

// Consentimentos LGPD
router.get('/consents', authenticateToken, userController.getConsents);
router.put('/consents', authenticateToken, userController.updateConsents);

// Exportar dados pessoais
router.post('/export-data', authenticateToken, userController.exportUserData);

// Gestão de exclusão de conta
router.post('/delete-account', authenticateToken, userController.requestAccountDeletion);
router.post('/cancel-deletion', authenticateToken, userController.cancelAccountDeletion);

// =================================================================
// ROTAS DE DEBUG (desenvolvimento)
// =================================================================
router.get('/debug', (req, res) => {
    res.json({
        message: 'Auth routes funcionando!',
        timestamp: new Date().toISOString(),
        routes: [
            'POST /auth/signup',
            'POST /auth/login', 
            'POST /auth/logout',
            'GET /auth/me',
            'PUT /auth/me',
            'GET /auth/stats',
            'GET /auth/consents',
            'PUT /auth/consents',
            'POST /auth/export-data',
            'POST /auth/delete-account',
            'POST /auth/cancel-deletion'
        ]
    });
});

router.get('/test', (req, res) => {
    res.json({
        status: 'ok',
        message: 'Auth routes test endpoint',
        timestamp: new Date().toISOString()
    });
});

module.exports = router;
