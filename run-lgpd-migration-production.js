// Script para aplicar migração LGPD no Render
const { Client } = require('pg');

async function runLgpdMigration() {
    const client = new Client({
        connectionString: process.env.DATABASE_URL,
        ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
    });

    try {
        await client.connect();
        console.log('Conectado ao banco de dados...');

        // Verificar se colunas já existem
        const checkQuery = `
            SELECT column_name 
            FROM information_schema.columns 
            WHERE table_name = 'users' 
            AND column_name IN ('gdpr_consent_date', 'gdpr_ip_address', 'gdpr_user_agent')
        `;

        const existingColumns = await client.query(checkQuery);
        console.log('Colunas existentes:', existingColumns.rows);

        if (existingColumns.rows.length === 0) {
            console.log('Aplicando migração LGPD...');

            // Aplicar migração LGPD básica primeiro
            const basicMigration = `
                -- Adicionar campos LGPD básicos na tabela users
                ALTER TABLE users ADD COLUMN IF NOT EXISTS gdpr_consent_date TIMESTAMP;
                ALTER TABLE users ADD COLUMN IF NOT EXISTS gdpr_ip_address VARCHAR(45);
                ALTER TABLE users ADD COLUMN IF NOT EXISTS gdpr_user_agent TEXT;
                ALTER TABLE users ADD COLUMN IF NOT EXISTS data_retention_until TIMESTAMP;
                ALTER TABLE users ADD COLUMN IF NOT EXISTS account_deletion_requested BOOLEAN DEFAULT FALSE;
                ALTER TABLE users ADD COLUMN IF NOT EXISTS account_deletion_scheduled TIMESTAMP;
            `;

            await client.query(basicMigration);
            console.log('✅ Campos LGPD adicionados na tabela users');

            // Criar tabela de consentimentos
            const consentsTable = `
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
            `;

            await client.query(consentsTable);
            console.log('✅ Tabela user_consents criada');

            console.log('🎉 Migração LGPD aplicada com sucesso!');
        } else {
            console.log('⚠️ Colunas LGPD já existem, atualizando apenas se necessário...');
            
            // Verificar se user_consents existe
            const tableCheck = await client.query(`
                SELECT table_name FROM information_schema.tables 
                WHERE table_name = 'user_consents'
            `);

            if (tableCheck.rows.length === 0) {
                const consentsTable = `
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
                `;
                await client.query(consentsTable);
                console.log('✅ Tabela user_consents criada');
            }
        }

        // Atualizar usuários existentes sem dados LGPD
        const updateExistingUsers = `
            UPDATE users 
            SET gdpr_consent_date = created_at,
                gdpr_ip_address = 'migrated',
                gdpr_user_agent = 'migration-script'
            WHERE gdpr_consent_date IS NULL;
        `;

        const result = await client.query(updateExistingUsers);
        console.log(`✅ ${result.rowCount} usuários existentes atualizados com dados LGPD`);

    } catch (error) {
        console.error('❌ Erro ao aplicar migração:', error);
        throw error;
    } finally {
        await client.end();
    }
}

// Executar se chamado diretamente
if (require.main === module) {
    runLgpdMigration()
        .then(() => {
            console.log('Migração concluída!');
            process.exit(0);
        })
        .catch(error => {
            console.error('Falha na migração:', error);
            process.exit(1);
        });
}

module.exports = { runLgpdMigration };
