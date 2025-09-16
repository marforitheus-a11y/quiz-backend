// =================================================================
// AUTH MIDDLEWARE - Middleware de autenticação JWT
// =================================================================

const jwt = require('jsonwebtoken');

function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ 
            error: 'Token de acesso requerido' 
        });
    }

    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) {
            return res.status(403).json({ 
                error: 'Token inválido' 
            });
        }

        req.user = user;
        next();
    });
}

function authenticateAdmin(req, res, next) {
    authenticateToken(req, res, () => {
        if (!req.user.is_admin) {
            return res.status(403).json({ 
                error: 'Acesso negado. Privilégios de admin requeridos.' 
            });
        }
        next();
    });
}

module.exports = authenticateToken;
module.exports.authenticateAdmin = authenticateAdmin;
