require('dotenv').config();
const jwt = require('jsonwebtoken');

// Criar um token válido para o test_user
const payload = {
    id: 82,
    username: 'test_user',
    role: 'user'
};

const token = jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: '8h' });

console.log('Token criado:', token);
console.log('Expires in 8 hours');

// Salvar token no arquivo
const fs = require('fs');
const path = require('path');
const tokenPath = path.join(__dirname, '..', 'quiz-frontend', 'token.txt');

fs.writeFileSync(tokenPath, token, 'utf8');
console.log('Token salvo em:', tokenPath);

process.exit(0);
