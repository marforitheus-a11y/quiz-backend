const express = require('express');
const passport = require('passport');
const jwt = require('jsonwebtoken');
const router = express.Router();

const JWT_SECRET = process.env.JWT_SECRET;

// Rota para iniciar a autenticação (ex: /google)
// O prefixo '/auth' será adicionado em server.js
router.get('/:provider', (req, res, next) => {
    const provider = req.params.provider;
    if (provider === 'google') {
        passport.authenticate(provider, { scope: ['profile', 'email'], prompt: 'select_account' })(req, res, next);
    } else if (provider === 'facebook') {
        passport.authenticate(provider, { scope: ['email'] })(req, res, next);
    } else {
        passport.authenticate(provider)(req, res, next);
    }
});

// Rota de callback após a autenticação (ex: /google/callback)
router.get('/:provider/callback', (req, res, next) => {
    const provider = req.params.provider;
    passport.authenticate(provider, (err, user, info) => {
        if (err || !user) {
            const failureRedirectUrl = `${process.env.FRONTEND_URL}/auth-failure.html?error=${encodeURIComponent(info?.message || 'Authentication failed')}`;
            return res.redirect(failureRedirectUrl);
        }
        
        const payload = { id: user.id, username: user.username, role: user.role };
        const token = jwt.sign(payload, JWT_SECRET, { expiresIn: '8h' });

        const successRedirectUrl = `${process.env.FRONTEND_URL}/auth-success.html?token=${token}`;
        res.redirect(successRedirectUrl);
    })(req, res, next);
});

module.exports = router;
