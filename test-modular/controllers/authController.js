// controllers/authController.js - Controlador de autenticação
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const db = require('../config/database');
const { JWT_SECRET } = require('../config/environment');

class AuthController {
  // Login
  static async login(req, res) {
    try {
      const { loginIdentifier, password } = req.body;

      if (!loginIdentifier || !password) {
        return res.status(400).json({
          status: 'error',
          message: 'Login e senha são obrigatórios'
        });
      }

      // Buscar usuário por username ou email
      const userQuery = `
        SELECT id, username, email, password, role, name 
        FROM users 
        WHERE username = $1 OR email = $1
      `;
      
      const result = await db.query(userQuery, [loginIdentifier]);

      if (result.rows.length === 0) {
        return res.status(401).json({
          status: 'error',
          message: 'Usuário ou senha inválidos.'
        });
      }

      const user = result.rows[0];
      const isValidPassword = await bcrypt.compare(password, user.password);

      if (!isValidPassword) {
        return res.status(401).json({
          status: 'error',
          message: 'Usuário ou senha inválidos.'
        });
      }

      // Gerar JWT token
      const token = jwt.sign(
        { 
          id: user.id, 
          username: user.username, 
          role: user.role 
        },
        JWT_SECRET,
        { expiresIn: '24h' }
      );

      res.json({
        status: 'success',
        message: 'Login bem-sucedido!',
        token,
        user: {
          id: user.id,
          username: user.username,
          email: user.email,
          name: user.name,
          role: user.role
        }
      });

    } catch (error) {
      console.error('Erro no login:', error);
      res.status(500).json({
        status: 'error',
        message: 'Erro interno do servidor'
      });
    }
  }

  // Registro
  static async register(req, res) {
    try {
      const { username, email, password, name } = req.body;

      if (!username || !email || !password) {
        return res.status(400).json({
          status: 'error',
          message: 'Username, email e senha são obrigatórios'
        });
      }

      // Verificar se usuário já existe
      const existingUser = await db.query(
        'SELECT id FROM users WHERE username = $1 OR email = $2',
        [username, email]
      );

      if (existingUser.rows.length > 0) {
        return res.status(409).json({
          status: 'error',
          message: 'Usuário ou email já existe'
        });
      }

      // Hash da senha
      const hashedPassword = await bcrypt.hash(password, 10);

      // Criar usuário
      const newUser = await db.query(
        `INSERT INTO users (username, email, password, name, role) 
         VALUES ($1, $2, $3, $4, $5) 
         RETURNING id, username, email, name, role`,
        [username, email, hashedPassword, name || username, 'user']
      );

      res.status(201).json({
        status: 'success',
        message: 'Usuário criado com sucesso!',
        user: newUser.rows[0]
      });

    } catch (error) {
      console.error('Erro no registro:', error);
      res.status(500).json({
        status: 'error',
        message: 'Erro interno do servidor'
      });
    }
  }

  // Logout
  static async logout(req, res) {
    res.json({
      status: 'success',
      message: 'Logout realizado com sucesso'
    });
  }

  // Perfil do usuário
  static async getProfile(req, res) {
    try {
      const userId = req.user.id;

      const result = await db.query(
        'SELECT id, username, email, name, role, created_at FROM users WHERE id = $1',
        [userId]
      );

      if (result.rows.length === 0) {
        return res.status(404).json({
          status: 'error',
          message: 'Usuário não encontrado'
        });
      }

      res.json({
        status: 'success',
        user: result.rows[0]
      });

    } catch (error) {
      console.error('Erro ao buscar perfil:', error);
      res.status(500).json({
        status: 'error',
        message: 'Erro interno do servidor'
      });
    }
  }
}

module.exports = AuthController;
