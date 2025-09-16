// config/environment.js - Configurações de ambiente
require('dotenv').config();

module.exports = {
  NODE_ENV: process.env.NODE_ENV || 'development',
  PORT: process.env.PORT || 4000, // Porta diferente para teste
  JWT_SECRET: process.env.JWT_SECRET,
  DB_CONFIG: {
    user: process.env.DB_USER,
    host: process.env.DB_HOST,
    database: process.env.DB_NAME,
    password: process.env.DB_PASSWORD,
    port: process.env.DB_PORT || 5432
  },
  CORS_ORIGINS: [
    'http://localhost:3000',
    'http://localhost:8080',
    'http://localhost:5500',
    'http://127.0.0.1:8080'
  ]
};
