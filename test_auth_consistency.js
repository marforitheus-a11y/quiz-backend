const { Pool } = require('pg');

// Configurar conexão com o banco (production)
const db = new Pool({
    connectionString: process.env.DATABASE_URL || 'postgres://quiz_db_user:GqJ5FlJ2QG8dmHoUBOoJU1DRdPINm1OY@dpg-ct7mvhjtq21c73bqjr80-a.oregon-postgres.render.com/quiz_db',
    ssl: { rejectUnauthorized: false }
});

async function testAuthConsistency() {
    console.log('🔍 Testando consistência de autenticação...\n');
    
    try {
        // 1. Verificar se as colunas existem
        const columnsResult = await db.query(`
            SELECT column_name, data_type, is_nullable 
            FROM information_schema.columns 
            WHERE table_name = 'users' 
            AND column_name IN ('role', 'is_admin')
            ORDER BY column_name;
        `);
        
        console.log('📋 Colunas na tabela users:');
        columnsResult.rows.forEach(col => {
            console.log(`  - ${col.column_name}: ${col.data_type} (nullable: ${col.is_nullable})`);
        });
        console.log();
        
        // 2. Verificar consistência entre role e is_admin
        const inconsistencyResult = await db.query(`
            SELECT 
                id, 
                email, 
                role, 
                is_admin,
                CASE 
                    WHEN role = 'admin' AND is_admin = true THEN 'Consistente'
                    WHEN role != 'admin' AND is_admin = false THEN 'Consistente'
                    ELSE 'INCONSISTENTE'
                END as status
            FROM users 
            ORDER BY id;
        `);
        
        console.log('👥 Usuários e status de consistência:');
        inconsistencyResult.rows.forEach(user => {
            const symbol = user.status === 'Consistente' ? '✅' : '❌';
            console.log(`  ${symbol} ID ${user.id}: ${user.email} | role: ${user.role} | is_admin: ${user.is_admin}`);
        });
        console.log();
        
        // 3. Contar inconsistências
        const inconsistentCount = inconsistencyResult.rows.filter(u => u.status === 'INCONSISTENTE').length;
        const totalUsers = inconsistencyResult.rows.length;
        
        console.log(`📊 Resumo:`);
        console.log(`  Total de usuários: ${totalUsers}`);
        console.log(`  Consistentes: ${totalUsers - inconsistentCount}`);
        console.log(`  Inconsistentes: ${inconsistentCount}`);
        
        if (inconsistentCount === 0) {
            console.log('✅ Todos os usuários estão com autenticação consistente!');
        } else {
            console.log('❌ Existem inconsistências que precisam ser corrigidas.');
        }
        
        // 4. Testar um login simulado
        console.log('\n🔐 Testando queries de autenticação...');
        
        const roleBasedQuery = await db.query(`
            SELECT COUNT(*) as count FROM users WHERE role != 'admin';
        `);
        
        console.log(`  Usuários não-admin (role-based): ${roleBasedQuery.rows[0].count}`);
        
        // Verificar se a query antiga ainda funciona (se a coluna is_admin existe)
        const hasIsAdmin = columnsResult.rows.some(col => col.column_name === 'is_admin');
        if (hasIsAdmin) {
            const isAdminQuery = await db.query(`
                SELECT COUNT(*) as count FROM users WHERE is_admin = false;
            `);
            console.log(`  Usuários não-admin (is_admin-based): ${isAdminQuery.rows[0].count}`);
            
            const match = roleBasedQuery.rows[0].count === isAdminQuery.rows[0].count;
            console.log(`  Queries combinam: ${match ? '✅' : '❌'}`);
        }
        
    } catch (error) {
        console.error('❌ Erro ao testar consistência:', error.message);
    } finally {
        await db.end();
    }
}

testAuthConsistency();