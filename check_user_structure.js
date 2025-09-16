require('dotenv').config();
const db = require('./db');

async function checkUserStructure() {
    try {
        console.log('🔍 Verificando estrutura da tabela users...');
        
        // Verificar se existe coluna is_admin
        const columnsResult = await db.query(`
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
            await db.query('ALTER TABLE users ADD COLUMN role VARCHAR(20) DEFAULT \'user\'');
            await db.query('UPDATE users SET role = CASE WHEN is_admin = true THEN \'admin\' ELSE \'user\' END');
            console.log('✅ Coluna role criada e populada');
        }
        
        // Se role existe mas is_admin não existe, criar is_admin baseado em role
        if (hasRole && !hasIsAdmin) {
            console.log('\n🔄 Adicionando coluna is_admin baseada em role...');
            await db.query('ALTER TABLE users ADD COLUMN is_admin BOOLEAN DEFAULT false');
            await db.query('UPDATE users SET is_admin = CASE WHEN role = \'admin\' THEN true ELSE false END');
            console.log('✅ Coluna is_admin criada e populada');
        }
        
        // Listar usuários
        console.log('\n👥 Usuários existentes:');
        const usersResult = await db.query('SELECT id, username, role, is_admin FROM users ORDER BY id');
        usersResult.rows.forEach(user => {
            console.log(`  ID: ${user.id} | Username: ${user.username} | Role: ${user.role || 'NULL'} | is_admin: ${user.is_admin !== undefined ? user.is_admin : 'NULL'}`);
        });
        
        // Verificar usuário teste
        console.log('\n🧪 Verificando usuário teste "brunaamor":');
        const testUserResult = await db.query('SELECT * FROM users WHERE username = $1', ['brunaamor']);
        
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
        
        process.exit(0);
    } catch (err) {
        console.error('❌ Erro:', err);
        process.exit(1);
    }
}

checkUserStructure();