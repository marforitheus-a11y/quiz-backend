// Script para aplicar migração LGPD no banco via API
const https = require('https');

async function applyLgpdMigrationViaApi() {
    const migrationData = {
        action: 'apply_lgpd_migration',
        sql: `
            -- Adicionar campos LGPD na tabela users se não existirem
            DO $$
            BEGIN
                IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'users' AND column_name = 'gdpr_consent_date') THEN
                    ALTER TABLE users ADD COLUMN gdpr_consent_date TIMESTAMP;
                    ALTER TABLE users ADD COLUMN gdpr_ip_address VARCHAR(45);
                    ALTER TABLE users ADD COLUMN gdpr_user_agent TEXT;
                    ALTER TABLE users ADD COLUMN data_retention_until TIMESTAMP;
                    ALTER TABLE users ADD COLUMN account_deletion_requested BOOLEAN DEFAULT FALSE;
                    ALTER TABLE users ADD COLUMN account_deletion_scheduled TIMESTAMP;
                END IF;
            END $$;

            -- Criar tabela de consentimentos se não existir
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
            WHERE gdpr_consent_date IS NULL OR gdpr_ip_address IS NULL;
        `
    };

    return new Promise((resolve, reject) => {
        const data = JSON.stringify(migrationData);
        
        const options = {
            hostname: 'quiz-api-z4ri.onrender.com',
            port: 443,
            path: '/admin/migrate',
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Content-Length': data.length,
                'Authorization': 'Bearer admin-migration-token'
            }
        };

        const req = https.request(options, (res) => {
            let responseData = '';
            
            res.on('data', (chunk) => {
                responseData += chunk;
            });
            
            res.on('end', () => {
                if (res.statusCode === 200) {
                    console.log('✅ Migração aplicada com sucesso via API');
                    resolve(responseData);
                } else {
                    console.log('❌ Falha na migração via API:', responseData);
                    reject(new Error(`API error: ${res.statusCode}`));
                }
            });
        });

        req.on('error', (error) => {
            console.log('❌ Erro de conexão:', error);
            reject(error);
        });

        req.write(data);
        req.end();
    });
}

console.log('Aplicando migração LGPD via commit no Render...');
console.log('A migração será executada automaticamente quando o código for deployed.');
console.log('✅ Script pronto para deploy');

module.exports = { applyLgpdMigrationViaApi };
