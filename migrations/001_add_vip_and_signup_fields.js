const db = require('../db');

async function migrate() {
    console.log('Iniciando migração do banco de dados...');
    try {
        // Adicionar colunas à tabela de usuários se não existirem
        console.log('Verificando e adicionando colunas à tabela "users"...');
        await db.query(`
            ALTER TABLE users
            ADD COLUMN IF NOT EXISTS name TEXT,
            ADD COLUMN IF NOT EXISTS email TEXT,
            ADD COLUMN IF NOT EXISTS is_vip BOOLEAN DEFAULT FALSE,
            ADD COLUMN IF NOT EXISTS subscription_expires_at TIMESTAMPA,
            ADD COLUMN IF NOT EXISTS last_quiz_date DATE,
            ADD COLUMN IF NOT EXISTS daily_quiz_count INTEGER DEFAULT 0;
        `);
        console.log('Colunas verificadas/adicionadas com sucesso.');

        // Adicionar constraint UNIQUE para email, se não existir
        const constraintExists = await db.query(`
            SELECT 1 FROM pg_constraint WHERE conname = 'users_email_key';
        `);
        if (constraintExists.rowCount === 0) {
            console.log('Adicionando constraint UNIQUE para a coluna "email"...');
            // Primeiro, garantir que não há emails duplicados (nulos ou vazios) que possam quebrar a constraint
            await db.query(`UPDATE users SET email = NULL WHERE email = ''`);
            await db.query(`
                UPDATE users u SET email = u.username || '@example.com'
                WHERE u.email IS NULL AND NOT EXISTS (SELECT 1 FROM users u2 WHERE u2.email = u.username || '@example.com');
            `);
            await db.query('ALTER TABLE users ADD CONSTRAINT users_email_key UNIQUE (email);');
            console.log('Constraint UNIQUE de email adicionada.');
        }

        // Atualizar todos os usuários existentes para serem VIP
        console.log('Atualizando usuários existentes para o status VIP...');
        const result = await db.query(`
            UPDATE users SET is_vip = TRUE WHERE is_vip IS NOT TRUE;
        `);
        console.log(`${result.rowCount} usuários existentes foram atualizados para VIP.`);

        console.log('Migração concluída com sucesso!');
    } catch (error) {
        console.error('Erro durante a migração:', error);
        process.exit(1);
    }
}

migrate().then(() => {
    console.log('Processo de migração finalizado.');
    process.exit(0);
});
