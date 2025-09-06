const GoogleStrategy = require('passport-google-oauth20').Strategy;
const FacebookStrategy = require('passport-facebook').Strategy;
const db = require('../db');
const { v4: uuidv4 } = require('uuid');

// Função auxiliar para encontrar ou criar um usuário
async function findOrCreateUser(profile, provider) {
    const email = profile.emails && profile.emails[0] ? profile.emails[0].value : null;
    if (!email) {
        throw new Error('O provedor não retornou um endereço de e-mail.');
    }

    try {
        // 1. Tenta encontrar o usuário pelo ID do provedor
        let userResult = await db.query(`SELECT * FROM users WHERE ${provider}_id = $1`, [profile.id]);
        if (userResult.rows.length > 0) {
            return userResult.rows[0];
        }

        // 2. Tenta encontrar o usuário pelo e-mail
        userResult = await db.query('SELECT * FROM users WHERE email = $1', [email]);
        if (userResult.rows.length > 0) {
            // Usuário com este e-mail já existe, vincula a conta
            const existingUser = userResult.rows[0];
            await db.query(`UPDATE users SET ${provider}_id = $1 WHERE id = $2`, [profile.id, existingUser.id]);
            return existingUser;
        }

        // 3. Cria um novo usuário
        const name = profile.displayName || 'Usuário';
        // Gera um nome de usuário único a partir do e-mail
        const usernameBase = email.split('@')[0].replace(/[^a-zA-Z0-9]/g, '');
        const username = `${usernameBase}_${uuidv4().substring(0, 4)}`;
        
        const newUserResult = await db.query(
            `INSERT INTO users (name, email, username, ${provider}_id, role, is_pay, daily_quiz_count)
             VALUES ($1, $2, $3, $4, 'user', false, 0)
             RETURNING *`,
            [name, email, username, profile.id]
        );
        return newUserResult.rows[0];

    } catch (err) {
        console.error(`Erro em findOrCreateUser para ${provider}:`, err);
        throw err;
    }
}

module.exports = function(passport) {
    // Estratégia do Google
    passport.use(new GoogleStrategy({
        clientID: process.env.GOOGLE_CLIENT_ID,
        clientSecret: process.env.GOOGLE_CLIENT_SECRET,
        callbackURL: 'https://quiz-api-z4ri.onrender.com/auth/google/callback'
    },
    async (accessToken, refreshToken, profile, done) => {
        try {
            const user = await findOrCreateUser(profile, 'google');
            return done(null, user);
        } catch (err) {
            return done(err, null);
        }
    }));

    // Estratégia do Facebook
    passport.use(new FacebookStrategy({
        clientID: process.env.FACEBOOK_APP_ID,
        clientSecret: process.env.FACEBOOK_APP_SECRET,
        callbackURL: 'https://quiz-api-z4ri.onrender.com/auth/facebook/callback',
        profileFields: ['id', 'displayName', 'emails']
    },
    async (accessToken, refreshToken, profile, done) => {
        try {
            const user = await findOrCreateUser(profile, 'facebook');
            return done(null, user);
        } catch (err) {
            return done(err, null);
        }
    }));

    // Serializa o usuário para a sessão
    passport.serializeUser((user, done) => {
        done(null, user.id);
    });

    // Desserializa o usuário da sessão
    passport.deserializeUser(async (id, done) => {
        try {
            const result = await db.query('SELECT * FROM users WHERE id = $1', [id]);
            done(null, result.rows[0]);
        } catch (err) {
            done(err, null);
        }
    });
};
