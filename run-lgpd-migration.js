// Script para aplicar migração LGPD ao banco de dados
const { Pool } = require('pg');
const fs = require('fs');
const path = require('path');

// Configuração do banco - usar a URL de produção se não houver local
const DATABASE_URL = process.env.DATABASE_URL || 'postgresql://quiz_backend_db_user:cQpPRLjkIKYG9G49Y2uLQ5sRKNpgaJwz@dpg-ct6cqjt6l47c73c8nfug-a.oregon-postgres.render.com/quiz_backend_db';

const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

async function runMigration() {
  console.log('🚀 Iniciando migração LGPD...');
  
  try {
    // Testar conexão
    console.log('🔗 Conectando ao banco de dados...');
    await pool.query('SELECT NOW()');
    console.log('✅ Conexão estabelecida com sucesso!');
    
    // Ler o arquivo de migração
    const migrationPath = path.join(__dirname, 'migrations', '002_lgpd_compliance.sql');
    const migrationSQL = fs.readFileSync(migrationPath, 'utf8');

    console.log('📄 Aplicando migração SQL...');

    // Dividir o SQL em comandos separados e executar um por vez
    const commands = migrationSQL.split(';').filter(cmd => cmd.trim().length > 0);
    
    for (const command of commands) {
      if (command.trim()) {
        try {
          await pool.query(command.trim());
        } catch (err) {
          // Ignorar erros de tabelas/funções que já existem
          if (err.message.includes('already exists') || 
              err.message.includes('duplicate column') ||
              err.message.includes('relation') && err.message.includes('already exists')) {
            console.log(`⚠️  Objeto já existe (ignorando): ${err.message.split('\n')[0]}`);
          } else {
            throw err;
          }
        }
      }
    }
    
    console.log('✅ Migração LGPD aplicada com sucesso!');
    console.log('📋 Tabelas criadas/verificadas:');
    console.log('   - user_consents (consentimentos detalhados)');
    console.log('   - consent_history (histórico para auditoria)');
    console.log('   - data_requests (solicitações LGPD)');
    console.log('   - data_access_logs (logs de acesso)');
    console.log('   - legal_documents (versionamento de documentos)');
    console.log('🔧 Triggers e funções criados para compliance');
    
    // Verificar se as tabelas foram criadas
    const tables = await pool.query(`
      SELECT table_name 
      FROM information_schema.tables 
      WHERE table_schema = 'public' 
      AND table_name IN ('user_consents', 'consent_history', 'data_requests', 'data_access_logs', 'legal_documents')
      ORDER BY table_name
    `);
    
    console.log('\n📊 Verificação das tabelas:');
    tables.rows.forEach(row => {
      console.log(`   ✓ ${row.table_name}`);
    });
    
    // Verificar colunas adicionadas na tabela users
    console.log('\n🔍 Verificando colunas LGPD na tabela users...');
    const userColumns = await pool.query(`
      SELECT column_name 
      FROM information_schema.columns 
      WHERE table_name = 'users' 
      AND column_name IN ('gdpr_consent_date', 'gdpr_ip_address', 'gdpr_user_agent', 'account_deletion_requested')
      ORDER BY column_name
    `);
    
    userColumns.rows.forEach(row => {
      console.log(`   ✓ users.${row.column_name}`);
    });
    
    console.log('\n🎉 Sistema LGPD está pronto para uso!');
    console.log('📌 Próximos passos:');
    console.log('   1. Reiniciar o servidor para carregar as novas rotas');
    console.log('   2. Testar as funcionalidades de consentimento');
    console.log('   3. Verificar formulário de cadastro com validações LGPD');
    
  } catch (error) {
    console.error('❌ Erro na migração:', error.message);
    console.error('📝 Detalhes:', error);
    process.exit(1);
  } finally {
    await pool.end();
  }
}

// Executar se chamado diretamente
if (require.main === module) {
  runMigration();
}

module.exports = { runMigration };
