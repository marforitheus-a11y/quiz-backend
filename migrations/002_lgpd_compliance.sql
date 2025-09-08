-- Migration: LGPD Compliance Tables
-- Criado em: 2025-09-08
-- Descrição: Adiciona campos e tabelas necessários para compliance com LGPD

-- 1. Adicionar campos LGPD na tabela users
ALTER TABLE users ADD COLUMN IF NOT EXISTS gdpr_consent_date TIMESTAMP;
ALTER TABLE users ADD COLUMN IF NOT EXISTS gdpr_ip_address VARCHAR(45);
ALTER TABLE users ADD COLUMN IF NOT EXISTS gdpr_user_agent TEXT;
ALTER TABLE users ADD COLUMN IF NOT EXISTS data_retention_until TIMESTAMP;
ALTER TABLE users ADD COLUMN IF NOT EXISTS account_deletion_requested BOOLEAN DEFAULT FALSE;
ALTER TABLE users ADD COLUMN IF NOT EXISTS account_deletion_scheduled TIMESTAMP;

-- 2. Criar tabela de consentimentos detalhados
CREATE TABLE IF NOT EXISTS user_consents (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    
    -- Consentimentos específicos
    essential_data BOOLEAN NOT NULL DEFAULT TRUE,
    performance_analysis BOOLEAN DEFAULT FALSE,
    personalization BOOLEAN DEFAULT FALSE,
    marketing_emails BOOLEAN DEFAULT FALSE,
    analytics_cookies BOOLEAN DEFAULT FALSE,
    
    -- Aceite de termos e políticas
    terms_accepted BOOLEAN NOT NULL DEFAULT FALSE,
    terms_accepted_at TIMESTAMP,
    terms_version VARCHAR(50) DEFAULT '1.0',
    privacy_policy_accepted BOOLEAN NOT NULL DEFAULT FALSE,
    privacy_policy_accepted_at TIMESTAMP,
    privacy_policy_version VARCHAR(50) DEFAULT '1.0',
    
    -- Metadados de compliance
    consent_method VARCHAR(100) DEFAULT 'explicit_checkbox', -- explicit_checkbox, implied, updated
    ip_address VARCHAR(45),
    user_agent TEXT,
    geolocation VARCHAR(100),
    
    -- Auditoria
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW(),
    
    UNIQUE(user_id)
);

-- 3. Criar tabela de histórico de consentimentos (para auditoria)
CREATE TABLE IF NOT EXISTS consent_history (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    consent_type VARCHAR(50) NOT NULL, -- essential, performance, marketing, etc.
    old_value BOOLEAN,
    new_value BOOLEAN,
    change_reason VARCHAR(255),
    ip_address VARCHAR(45),
    user_agent TEXT,
    created_at TIMESTAMP DEFAULT NOW()
);

-- 4. Criar tabela de solicitações de dados (LGPD Rights)
CREATE TABLE IF NOT EXISTS data_requests (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    request_type VARCHAR(50) NOT NULL, -- export, delete, correction, information, portability
    status VARCHAR(50) DEFAULT 'pending', -- pending, processing, completed, denied
    request_details TEXT,
    response_details TEXT,
    requested_at TIMESTAMP DEFAULT NOW(),
    processed_at TIMESTAMP,
    completed_at TIMESTAMP,
    processor_user_id INTEGER REFERENCES users(id),
    
    -- Metadados
    ip_address VARCHAR(45),
    user_agent TEXT,
    
    -- Para solicitações de exportação
    export_file_path VARCHAR(255),
    export_expires_at TIMESTAMP
);

-- 5. Criar tabela de logs de acesso a dados (auditoria LGPD)
CREATE TABLE IF NOT EXISTS data_access_logs (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    accessed_by_user_id INTEGER REFERENCES users(id), -- quem acessou os dados
    access_type VARCHAR(50) NOT NULL, -- view, export, modify, delete
    data_category VARCHAR(100), -- personal_data, performance_data, etc.
    description TEXT,
    ip_address VARCHAR(45),
    user_agent TEXT,
    created_at TIMESTAMP DEFAULT NOW()
);

-- 6. Criar tabela de políticas e termos (versionamento)
CREATE TABLE IF NOT EXISTS legal_documents (
    id SERIAL PRIMARY KEY,
    document_type VARCHAR(50) NOT NULL, -- terms_of_service, privacy_policy
    version VARCHAR(50) NOT NULL,
    title VARCHAR(255) NOT NULL,
    content TEXT NOT NULL,
    effective_date TIMESTAMP NOT NULL,
    created_at TIMESTAMP DEFAULT NOW(),
    created_by INTEGER REFERENCES users(id),
    is_active BOOLEAN DEFAULT TRUE,
    
    UNIQUE(document_type, version)
);

-- 7. Criar índices para performance
CREATE INDEX IF NOT EXISTS idx_user_consents_user_id ON user_consents(user_id);
CREATE INDEX IF NOT EXISTS idx_consent_history_user_id ON consent_history(user_id);
CREATE INDEX IF NOT EXISTS idx_consent_history_created_at ON consent_history(created_at);
CREATE INDEX IF NOT EXISTS idx_data_requests_user_id ON data_requests(user_id);
CREATE INDEX IF NOT EXISTS idx_data_requests_status ON data_requests(status);
CREATE INDEX IF NOT EXISTS idx_data_access_logs_user_id ON data_access_logs(user_id);
CREATE INDEX IF NOT EXISTS idx_data_access_logs_created_at ON data_access_logs(created_at);

-- 8. Inserir documentos legais iniciais
INSERT INTO legal_documents (document_type, version, title, content, effective_date, is_active) VALUES
('terms_of_service', '1.0', 'Termos de Uso', 'Termos de uso da plataforma Quiz Concursos...', NOW(), TRUE),
('privacy_policy', '1.0', 'Política de Privacidade', 'Política de privacidade conforme LGPD...', NOW(), TRUE)
ON CONFLICT (document_type, version) DO NOTHING;

-- 9. Função para automatizar limpeza de dados expirados
CREATE OR REPLACE FUNCTION cleanup_expired_data()
RETURNS void AS $$
BEGIN
    -- Deletar logs de acesso antigos (manter apenas 2 anos)
    DELETE FROM data_access_logs 
    WHERE created_at < NOW() - INTERVAL '2 years';
    
    -- Deletar histórico de consentimentos antigo (manter apenas 5 anos)
    DELETE FROM consent_history 
    WHERE created_at < NOW() - INTERVAL '5 years';
    
    -- Deletar arquivos de exportação expirados
    DELETE FROM data_requests 
    WHERE request_type = 'export' 
    AND export_expires_at < NOW();
    
    -- Log da limpeza
    RAISE NOTICE 'LGPD cleanup completed at %', NOW();
END;
$$ LANGUAGE plpgsql;

-- 10. Trigger para registrar mudanças de consentimentos
CREATE OR REPLACE FUNCTION log_consent_changes()
RETURNS TRIGGER AS $$
BEGIN
    -- Se não é um INSERT e houve mudança, registrar no histórico
    IF TG_OP = 'UPDATE' THEN
        -- Verificar cada campo de consentimento
        IF OLD.essential_data != NEW.essential_data THEN
            INSERT INTO consent_history (user_id, consent_type, old_value, new_value, change_reason)
            VALUES (NEW.user_id, 'essential_data', OLD.essential_data, NEW.essential_data, 'User updated consent');
        END IF;
        
        IF OLD.performance_analysis != NEW.performance_analysis THEN
            INSERT INTO consent_history (user_id, consent_type, old_value, new_value, change_reason)
            VALUES (NEW.user_id, 'performance_analysis', OLD.performance_analysis, NEW.performance_analysis, 'User updated consent');
        END IF;
        
        IF OLD.personalization != NEW.personalization THEN
            INSERT INTO consent_history (user_id, consent_type, old_value, new_value, change_reason)
            VALUES (NEW.user_id, 'personalization', OLD.personalization, NEW.personalization, 'User updated consent');
        END IF;
        
        IF OLD.marketing_emails != NEW.marketing_emails THEN
            INSERT INTO consent_history (user_id, consent_type, old_value, new_value, change_reason)
            VALUES (NEW.user_id, 'marketing_emails', OLD.marketing_emails, NEW.marketing_emails, 'User updated consent');
        END IF;
        
        IF OLD.analytics_cookies != NEW.analytics_cookies THEN
            INSERT INTO consent_history (user_id, consent_type, old_value, new_value, change_reason)
            VALUES (NEW.user_id, 'analytics_cookies', OLD.analytics_cookies, NEW.analytics_cookies, 'User updated consent');
        END IF;
        
        -- Atualizar timestamp de modificação
        NEW.updated_at = NOW();
    END IF;
    
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Criar o trigger
DROP TRIGGER IF EXISTS consent_changes_trigger ON user_consents;
CREATE TRIGGER consent_changes_trigger
    BEFORE UPDATE ON user_consents
    FOR EACH ROW
    EXECUTE FUNCTION log_consent_changes();

-- 11. Comentários para documentação
COMMENT ON TABLE user_consents IS 'Armazena consentimentos detalhados do usuário conforme LGPD';
COMMENT ON TABLE consent_history IS 'Histórico de mudanças de consentimentos para auditoria LGPD';
COMMENT ON TABLE data_requests IS 'Solicitações de direitos do titular (LGPD Art. 18)';
COMMENT ON TABLE data_access_logs IS 'Logs de acesso a dados pessoais para auditoria';
COMMENT ON TABLE legal_documents IS 'Versionamento de termos e políticas de privacidade';

-- 12. Grant permissions (ajustar conforme necessário)
-- GRANT ALL PRIVILEGES ON user_consents TO your_app_user;
-- GRANT ALL PRIVILEGES ON consent_history TO your_app_user;
-- GRANT ALL PRIVILEGES ON data_requests TO your_app_user;
-- GRANT ALL PRIVILEGES ON data_access_logs TO your_app_user;
-- GRANT ALL PRIVILEGES ON legal_documents TO your_app_user;

-- Fim da migration
SELECT 'LGPD Compliance tables created successfully!' as status;
