// =================================================================
// USER CONTROLLER - Gestão completa de usuários e LGPD
// =================================================================

const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const db = require('../config/database');
const { v4: uuidv4 } = require('uuid');

// Verificar e aplicar migração LGPD
async function ensureLgpdCompliance() {
    try {
        console.log('🔍 Verificando compliance LGPD...');
        
        // Verificar se colunas LGPD existem
        const checkQuery = `
            SELECT column_name 
            FROM information_schema.columns 
            WHERE table_name = 'users' 
            AND column_name = 'gdpr_consent_date'
        `;
        
        const result = await db.query(checkQuery);
        
        if (result.rows.length === 0) {
            console.log('⚙️ Aplicando migração LGPD...');
            
            const lgpdMigration = `
                -- Adicionar campos LGPD na tabela users
                ALTER TABLE users ADD COLUMN IF NOT EXISTS gdpr_consent_date TIMESTAMP;
                ALTER TABLE users ADD COLUMN IF NOT EXISTS gdpr_ip_address VARCHAR(45);
                ALTER TABLE users ADD COLUMN IF NOT EXISTS gdpr_user_agent TEXT;
                ALTER TABLE users ADD COLUMN IF NOT EXISTS data_retention_until TIMESTAMP;
                ALTER TABLE users ADD COLUMN IF NOT EXISTS account_deletion_requested BOOLEAN DEFAULT FALSE;
                ALTER TABLE users ADD COLUMN IF NOT EXISTS account_deletion_scheduled TIMESTAMP;

                -- Criar tabela de consentimentos
                CREATE TABLE IF NOT EXISTS user_consents (
                    id SERIAL PRIMARY KEY,
                    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
                    essential_data BOOLEAN NOT NULL DEFAULT TRUE,
                    performance_analysis BOOLEAN DEFAULT FALSE,
                    personalization BOOLEAN DEFAULT FALSE,
                    marketing_emails BOOLEAN DEFAULT FALSE,
                    analytics_cookies BOOLEAN DEFAULT FALSE,
                    terms_accepted BOOLEAN NOT NULL DEFAULT FALSE,
                    terms_accepted_at TIMESTAMP,
                    terms_version VARCHAR(50) DEFAULT '1.0',
                    privacy_policy_accepted BOOLEAN NOT NULL DEFAULT FALSE,
                    privacy_policy_accepted_at TIMESTAMP,
                    privacy_policy_version VARCHAR(50) DEFAULT '1.0',
                    consent_method VARCHAR(100) DEFAULT 'explicit_checkbox',
                    ip_address VARCHAR(45),
                    user_agent TEXT,
                    geolocation VARCHAR(100),
                    created_at TIMESTAMP DEFAULT NOW(),
                    updated_at TIMESTAMP DEFAULT NOW(),
                    UNIQUE(user_id)
                );

                -- Atualizar usuários existentes
                UPDATE users 
                SET gdpr_consent_date = COALESCE(gdpr_consent_date, created_at),
                    gdpr_ip_address = COALESCE(gdpr_ip_address, 'migrated'),
                    gdpr_user_agent = COALESCE(gdpr_user_agent, 'migration-script')
                WHERE gdpr_consent_date IS NULL;
            `;
            
            await db.query(lgpdMigration);
            console.log('✅ Migração LGPD aplicada com sucesso!');
        } else {
            console.log('✅ LGPD compliance já configurado');
        }
    } catch (error) {
        console.error('❌ Erro na migração LGPD:', error);
    }
}

// Executar migração na inicialização
ensureLgpdCompliance();

// =================================================================
// REGISTRO DE USUÁRIO
// =================================================================
async function signup(req, res) {
    const { username, email, password, terms_accepted, privacy_policy_accepted } = req.body;
    
    // Validações básicas
    if (!username || !email || !password) {
        return res.status(400).json({ 
            error: 'Username, email e password são obrigatórios' 
        });
    }

    if (!terms_accepted || !privacy_policy_accepted) {
        return res.status(400).json({ 
            error: 'Aceitação dos termos e política de privacidade é obrigatória' 
        });
    }

    try {
        // Verificar se usuário já existe
        const existingUser = await db.query(
            'SELECT id FROM users WHERE username = $1 OR email = $2',
            [username, email]
        );

        if (existingUser.rows.length > 0) {
            return res.status(409).json({ 
                error: 'Usuário ou email já existe' 
            });
        }

        // Hash da senha
        const saltRounds = 12;
        const hashedPassword = await bcrypt.hash(password, saltRounds);

        // Dados do cliente para LGPD
        const clientIp = req.ip || req.connection.remoteAddress || 'unknown';
        const userAgent = req.headers['user-agent'] || 'unknown';

        // Inserir usuário
        const insertUserQuery = `
            INSERT INTO users (
                username, email, password, is_admin, created_at,
                gdpr_consent_date, gdpr_ip_address, gdpr_user_agent,
                data_retention_until, account_deletion_requested
            ) VALUES ($1, $2, $3, $4, NOW(), NOW(), $5, $6, NOW() + INTERVAL '7 years', FALSE)
            RETURNING id, username, email, is_admin, created_at
        `;

        const userResult = await db.query(insertUserQuery, [
            username, email, hashedPassword, false, clientIp, userAgent
        ]);

        const user = userResult.rows[0];

        // Inserir consentimentos LGPD
        const consentQuery = `
            INSERT INTO user_consents (
                user_id, essential_data, performance_analysis, personalization,
                marketing_emails, analytics_cookies, terms_accepted, terms_accepted_at,
                terms_version, privacy_policy_accepted, privacy_policy_accepted_at,
                privacy_policy_version, consent_method, ip_address, user_agent
            ) VALUES ($1, TRUE, FALSE, FALSE, FALSE, FALSE, $2, NOW(), '1.0', $3, NOW(), '1.0', 'explicit_signup', $4, $5)
        `;

        await db.query(consentQuery, [
            user.id, terms_accepted, privacy_policy_accepted, clientIp, userAgent
        ]);

        // Gerar token JWT
        const token = jwt.sign(
            { userId: user.id, username: user.username },
            process.env.JWT_SECRET,
            { expiresIn: '24h' }
        );

        console.log(`✅ Novo usuário criado: ${username} (ID: ${user.id})`);

        res.status(201).json({
            message: 'Usuário criado com sucesso',
            user: {
                id: user.id,
                username: user.username,
                email: user.email,
                is_admin: user.is_admin,
                created_at: user.created_at
            },
            token
        });

    } catch (error) {
        console.error('❌ Erro no signup:', error);
        res.status(500).json({ 
            error: 'Erro interno do servidor' 
        });
    }
}

// =================================================================
// LOGIN
// =================================================================
async function login(req, res) {
    const { loginIdentifier, password } = req.body;

    if (!loginIdentifier || !password) {
        return res.status(400).json({ 
            error: 'Login e password são obrigatórios' 
        });
    }

    try {
        // Buscar usuário por username ou email
        const userQuery = `
            SELECT id, username, email, password, is_admin, created_at
            FROM users 
            WHERE username = $1 OR email = $1
            AND account_deletion_requested = FALSE
        `;
        
        const userResult = await db.query(userQuery, [loginIdentifier]);

        if (userResult.rows.length === 0) {
            return res.status(401).json({ 
                error: 'Credenciais inválidas' 
            });
        }

        const user = userResult.rows[0];

        // Verificar senha
        const isValidPassword = await bcrypt.compare(password, user.password);
        
        if (!isValidPassword) {
            return res.status(401).json({ 
                error: 'Credenciais inválidas' 
            });
        }

        // Gerar token JWT
        const token = jwt.sign(
            { userId: user.id, username: user.username },
            process.env.JWT_SECRET,
            { expiresIn: '24h' }
        );

        console.log(`✅ Login realizado: ${user.username} (ID: ${user.id})`);

        res.json({
            message: 'Login realizado com sucesso',
            user: {
                id: user.id,
                username: user.username,
                email: user.email,
                is_admin: user.is_admin,
                created_at: user.created_at
            },
            token
        });

    } catch (error) {
        console.error('❌ Erro no login:', error);
        res.status(500).json({ 
            error: 'Erro interno do servidor' 
        });
    }
}

// =================================================================
// LOGOUT
// =================================================================
function logout(req, res) {
    res.json({ 
        message: 'Logout realizado com sucesso' 
    });
}

// =================================================================
// OBTER PERFIL DO USUÁRIO
// =================================================================
async function getProfile(req, res) {
    try {
        const userId = req.user.userId;

        const userQuery = `
            SELECT id, username, email, is_admin, created_at,
                   gdpr_consent_date, data_retention_until,
                   account_deletion_requested, account_deletion_scheduled
            FROM users 
            WHERE id = $1
        `;

        const userResult = await db.query(userQuery, [userId]);

        if (userResult.rows.length === 0) {
            return res.status(404).json({ 
                error: 'Usuário não encontrado' 
            });
        }

        const user = userResult.rows[0];

        res.json({
            user: {
                id: user.id,
                username: user.username,
                email: user.email,
                is_admin: user.is_admin,
                created_at: user.created_at,
                gdpr_consent_date: user.gdpr_consent_date,
                data_retention_until: user.data_retention_until,
                account_deletion_requested: user.account_deletion_requested,
                account_deletion_scheduled: user.account_deletion_scheduled
            }
        });

    } catch (error) {
        console.error('❌ Erro ao obter perfil:', error);
        res.status(500).json({ 
            error: 'Erro interno do servidor' 
        });
    }
}

// =================================================================
// ATUALIZAR PERFIL
// =================================================================
async function updateProfile(req, res) {
    try {
        const userId = req.user.userId;
        const { email } = req.body;

        if (!email) {
            return res.status(400).json({ 
                error: 'Email é obrigatório' 
            });
        }

        // Verificar se email já existe
        const existingEmailQuery = `
            SELECT id FROM users 
            WHERE email = $1 AND id != $2
        `;
        
        const existingEmail = await db.query(existingEmailQuery, [email, userId]);

        if (existingEmail.rows.length > 0) {
            return res.status(409).json({ 
                error: 'Email já está em uso' 
            });
        }

        // Atualizar email
        const updateQuery = `
            UPDATE users 
            SET email = $1 
            WHERE id = $2
            RETURNING id, username, email, is_admin, created_at
        `;

        const result = await db.query(updateQuery, [email, userId]);

        console.log(`✅ Perfil atualizado: ${result.rows[0].username}`);

        res.json({
            message: 'Perfil atualizado com sucesso',
            user: result.rows[0]
        });

    } catch (error) {
        console.error('❌ Erro ao atualizar perfil:', error);
        res.status(500).json({ 
            error: 'Erro interno do servidor' 
        });
    }
}

// =================================================================
// CONSENTIMENTOS LGPD
// =================================================================
async function getConsents(req, res) {
    try {
        const userId = req.user.userId;

        const query = `
            SELECT * FROM user_consents 
            WHERE user_id = $1
        `;

        const result = await db.query(query, [userId]);

        res.json({
            consents: result.rows[0] || {}
        });

    } catch (error) {
        console.error('❌ Erro ao obter consentimentos:', error);
        res.status(500).json({ 
            error: 'Erro interno do servidor' 
        });
    }
}

async function updateConsents(req, res) {
    try {
        const userId = req.user.userId;
        const {
            performance_analysis,
            personalization,
            marketing_emails,
            analytics_cookies
        } = req.body;

        const updateQuery = `
            UPDATE user_consents 
            SET performance_analysis = $1,
                personalization = $2,
                marketing_emails = $3,
                analytics_cookies = $4,
                updated_at = NOW()
            WHERE user_id = $5
            RETURNING *
        `;

        const result = await db.query(updateQuery, [
            performance_analysis, personalization, marketing_emails, 
            analytics_cookies, userId
        ]);

        console.log(`✅ Consentimentos atualizados para usuário ${userId}`);

        res.json({
            message: 'Consentimentos atualizados com sucesso',
            consents: result.rows[0]
        });

    } catch (error) {
        console.error('❌ Erro ao atualizar consentimentos:', error);
        res.status(500).json({ 
            error: 'Erro interno do servidor' 
        });
    }
}

// =================================================================
// EXPORTAR DADOS PESSOAIS
// =================================================================
async function exportUserData(req, res) {
    try {
        const userId = req.user.userId;

        // Dados do usuário
        const userQuery = `
            SELECT id, username, email, is_admin, created_at,
                   gdpr_consent_date, gdpr_ip_address, gdpr_user_agent,
                   data_retention_until, account_deletion_requested
            FROM users WHERE id = $1
        `;

        // Consentimentos
        const consentsQuery = `
            SELECT * FROM user_consents WHERE user_id = $1
        `;

        // Histórico de quizzes
        const historyQuery = `
            SELECT id, theme, total_questions, correct_answers, 
                   percentage, time_taken, created_at
            FROM quiz_history WHERE user_id = $1
        `;

        const [userData, consentsData, historyData] = await Promise.all([
            db.query(userQuery, [userId]),
            db.query(consentsQuery, [userId]),
            db.query(historyQuery, [userId])
        ]);

        const exportData = {
            user_data: userData.rows[0],
            consents: consentsData.rows[0] || {},
            quiz_history: historyData.rows,
            export_date: new Date().toISOString(),
            data_format: 'JSON',
            export_version: '1.0'
        };

        console.log(`✅ Dados exportados para usuário ${userId}`);

        res.json({
            message: 'Dados exportados com sucesso',
            data: exportData
        });

    } catch (error) {
        console.error('❌ Erro na exportação de dados:', error);
        res.status(500).json({ 
            error: 'Erro interno do servidor' 
        });
    }
}

// =================================================================
// SOLICITAR EXCLUSÃO DE CONTA
// =================================================================
async function requestAccountDeletion(req, res) {
    try {
        const userId = req.user.userId;
        const { confirmation } = req.body;

        if (confirmation !== 'DELETE_MY_ACCOUNT') {
            return res.status(400).json({
                error: 'Confirmação inválida. Digite "DELETE_MY_ACCOUNT" para confirmar.'
            });
        }

        // Agendar exclusão para 30 dias
        const deletionDate = new Date();
        deletionDate.setDate(deletionDate.getDate() + 30);

        const updateQuery = `
            UPDATE users 
            SET account_deletion_requested = TRUE,
                account_deletion_scheduled = $1
            WHERE id = $2
            RETURNING username
        `;

        const result = await db.query(updateQuery, [deletionDate, userId]);

        console.log(`⚠️ Exclusão solicitada: ${result.rows[0].username} (ID: ${userId})`);

        res.json({
            message: 'Solicitação de exclusão registrada',
            deletion_scheduled: deletionDate,
            grace_period_days: 30,
            note: 'Você pode cancelar esta solicitação dentro de 30 dias'
        });

    } catch (error) {
        console.error('❌ Erro na solicitação de exclusão:', error);
        res.status(500).json({ 
            error: 'Erro interno do servidor' 
        });
    }
}

// =================================================================
// CANCELAR EXCLUSÃO DE CONTA
// =================================================================
async function cancelAccountDeletion(req, res) {
    try {
        const userId = req.user.userId;

        const updateQuery = `
            UPDATE users 
            SET account_deletion_requested = FALSE,
                account_deletion_scheduled = NULL
            WHERE id = $1
            RETURNING username
        `;

        const result = await db.query(updateQuery, [userId]);

        console.log(`✅ Exclusão cancelada: ${result.rows[0].username} (ID: ${userId})`);

        res.json({
            message: 'Solicitação de exclusão cancelada com sucesso'
        });

    } catch (error) {
        console.error('❌ Erro ao cancelar exclusão:', error);
        res.status(500).json({ 
            error: 'Erro interno do servidor' 
        });
    }
}

// =================================================================
// ESTATÍSTICAS DO USUÁRIO
// =================================================================
async function getUserStats(req, res) {
    try {
        const userId = req.user.userId;

        const statsQuery = `
            SELECT 
                COUNT(*) as total_quizzes,
                AVG(percentage) as average_score,
                MAX(percentage) as best_score,
                MIN(percentage) as worst_score,
                SUM(time_taken) as total_time,
                COUNT(DISTINCT theme) as themes_played
            FROM quiz_history 
            WHERE user_id = $1
        `;

        const result = await db.query(statsQuery, [userId]);
        const stats = result.rows[0];

        res.json({
            stats: {
                total_quizzes: parseInt(stats.total_quizzes),
                average_score: parseFloat(stats.average_score) || 0,
                best_score: parseFloat(stats.best_score) || 0,
                worst_score: parseFloat(stats.worst_score) || 0,
                total_time_seconds: parseInt(stats.total_time) || 0,
                themes_played: parseInt(stats.themes_played)
            }
        });

    } catch (error) {
        console.error('❌ Erro ao obter estatísticas:', error);
        res.status(500).json({ 
            error: 'Erro interno do servidor' 
        });
    }
}

module.exports = {
    signup,
    login,
    logout,
    getProfile,
    updateProfile,
    getConsents,
    updateConsents,
    exportUserData,
    requestAccountDeletion,
    cancelAccountDeletion,
    getUserStats
};
