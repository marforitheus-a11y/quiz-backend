// routes/authRoutes.js - Rotas de autenticação
const express = require('express');
const router = express.Router();
const AuthController = require('../controllers/authController');
const { authenticateToken } = require('../middlewares/auth');

// Rotas públicas
router.post('/login', AuthController.login);
router.post('/signup', AuthController.register);
router.post('/register', AuthController.register);

// Rotas protegidas
router.post('/logout', authenticateToken, AuthController.logout);
router.get('/me', authenticateToken, AuthController.getProfile);

module.exports = router;
