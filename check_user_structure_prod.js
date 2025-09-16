// Forçar uso do banco de produção
process.env.NODE_ENV = 'production';
process.env.DATABASE_URL = 'postgresql://quiz_system_user:PD0uaBKLGOqNQvh4SgFOE7xtfEVMOdQH@dpg-crqaq3pu0jms73c0lh40-a.oregon-postgres.render.com/quiz_system';

const { Pool } = require('pg');

const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: { rejectUnauthorized: false }
});

async function checkUserStructure() {
    try {
        console.log('🔍 Verificando estrutura da tabela users (PRODUÇÃO)...');
        
        // Verificar se existe coluna is_admin
        const columnsResult = await pool.query(`
            SELECT column_name, data_type, is_nullable, column_default
            FROM information_schema.columns 
            WHERE table_name = 'users' 
            ORDER BY ordinal_position
        `);
        
        console.log('\n📋 Colunas da tabela users:');
        columnsResult.rows.forEach(col => {
            console.log(`  - ${col.column_name} (${col.data_type}) ${col.is_nullable === 'YES' ? 'NULL' : 'NOT NULL'} ${col.column_default ? `DEFAULT ${col.column_default}` : ''}`);
        });
        
        const hasIsAdmin = columnsResult.rows.some(col => col.column_name === 'is_admin');
        const hasRole = columnsResult.rows.some(col => col.column_name === 'role');
        
        console.log(`\n📊 Análise:
  - Coluna 'role': ${hasRole ? '✅ Existe' : '❌ Não existe'}
  - Coluna 'is_admin': ${hasIsAdmin ? '✅ Existe' : '❌ Não existe'}`);
        
        // Se is_admin existe mas role não existe, criar role baseado em is_admin
        if (hasIsAdmin && !hasRole) {
            console.log('\n🔄 Adicionando coluna role baseada em is_admin...');
            await pool.query('ALTER TABLE users ADD COLUMN role VARCHAR(20) DEFAULT \'user\'');
            await pool.query('UPDATE users SET role = CASE WHEN is_admin = true THEN \'admin\' ELSE \'user\' END');
            console.log('✅ Coluna role criada e populada');
        }
        
        // Se role existe mas is_admin não existe, criar is_admin baseado em role
        if (hasRole && !hasIsAdmin) {
            console.log('\n🔄 Adicionando coluna is_admin baseada em role...');
            await pool.query('ALTER TABLE users ADD COLUMN is_admin BOOLEAN DEFAULT false');
            await pool.query('UPDATE users SET is_admin = CASE WHEN role = \'admin\' THEN true ELSE false END');
            console.log('✅ Coluna is_admin criada e populada');
        }
        
        // Listar usuários (limitado a 10 para não spam)
        console.log('\n👥 Usuários existentes (primeiros 10):');
        const usersResult = await pool.query('SELECT id, username, role, is_admin FROM users ORDER BY id LIMIT 10');
        usersResult.rows.forEach(user => {
            console.log(`  ID: ${user.id} | Username: ${user.username} | Role: ${user.role || 'NULL'} | is_admin: ${user.is_admin !== undefined ? user.is_admin : 'NULL'}`);
        });
        
        // Verificar usuário teste
        console.log('\n🧪 Verificando usuário teste "brunaamor":');
        const testUserResult = await pool.query('SELECT * FROM users WHERE username = $1', ['brunaamor']);
        
        if (testUserResult.rows.length === 0) {
            console.log('❌ Usuário brunaamor não encontrado');
        } else {
            const user = testUserResult.rows[0];
            console.log('✅ Usuário brunaamor encontrado:');
            console.log(`  - ID: ${user.id}`);
            console.log(`  - Username: ${user.username}`);
            console.log(`  - Role: ${user.role}`);
            console.log(`  - is_admin: ${user.is_admin}`);
            console.log(`  - Email: ${user.email || 'NULL'}`);
        }
        
        // Verificar total de usuários por role
        console.log('\n📊 Estatísticas de usuários por role:');
        const statsResult = await pool.query(`
            SELECT 
                role,
                COUNT(*) as total,
                COUNT(CASE WHEN is_admin = true THEN 1 END) as admin_count
            FROM users 
            GROUP BY role 
            ORDER BY role
        `);
        
        statsResult.rows.forEach(stat => {
            console.log(`  Role "${stat.role}": ${stat.total} usuários (${stat.admin_count} marcados como admin)`);
        });
        
        await pool.end();
        process.exit(0);
    } catch (err) {
        console.error('❌ Erro:', err);
        process.exit(1);
    }
}

checkUserStructure();