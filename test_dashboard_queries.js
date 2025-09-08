const { Pool } = require('pg');

const db = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

async function testQueries() {
    try {
        console.log('Testando queries do dashboard...\n');
        
        // Test 1: Taxa de crescimento de usuários
        console.log('1. Testando query de crescimento de usuários...');
        try {
            const growthResult = await db.query(`
                SELECT 
                    COUNT(CASE WHEN created_at > CURRENT_DATE - INTERVAL '30 days' THEN 1 END) as new_users_last_30,
                    COUNT(CASE WHEN created_at BETWEEN CURRENT_DATE - INTERVAL '60 days' AND CURRENT_DATE - INTERVAL '30 days' THEN 1 END) as new_users_prev_30
                FROM users
                WHERE is_admin = false
            `);
            console.log('✓ Query de crescimento funcionou:', growthResult.rows[0]);
        } catch (err) {
            console.log('✗ Erro na query de crescimento:', err.message);
        }
        
        // Test 2: Usuários ativos
        console.log('\n2. Testando query de usuários ativos...');
        try {
            const activeUsersResult = await db.query(`
                SELECT COUNT(DISTINCT user_id) as count 
                FROM quiz_sessions 
                WHERE created_at > CURRENT_DATE - INTERVAL '30 days'
            `);
            console.log('✓ Query de usuários ativos funcionou:', activeUsersResult.rows[0]);
        } catch (err) {
            console.log('✗ Erro na query de usuários ativos:', err.message);
        }
        
        // Test 3: Usuários recentes
        console.log('\n3. Testando query de usuários recentes...');
        try {
            const recentUsersResult = await db.query(`
                SELECT COUNT(*) as count 
                FROM users 
                WHERE created_at > CURRENT_DATE - INTERVAL '30 days'
                AND is_admin = false
            `);
            console.log('✓ Query de usuários recentes funcionou:', recentUsersResult.rows[0]);
        } catch (err) {
            console.log('✗ Erro na query de usuários recentes:', err.message);
        }
        
        // Test 4: Sessões por dia
        console.log('\n4. Testando query de sessões por dia...');
        try {
            const sessionsResult = await db.query(`
                SELECT 
                    DATE(created_at) as date,
                    COUNT(*) as count
                FROM quiz_sessions 
                WHERE created_at > CURRENT_DATE - INTERVAL '7 days'
                GROUP BY DATE(created_at)
                ORDER BY date DESC
            `);
            console.log('✓ Query de sessões por dia funcionou:', sessionsResult.rows);
        } catch (err) {
            console.log('✗ Erro na query de sessões por dia:', err.message);
        }
        
        // Test 5: Top usuários
        console.log('\n5. Testando query de top usuários...');
        try {
            const topUsersResult = await db.query(`
                SELECT 
                    u.username,
                    u.email,
                    COUNT(qs.id) as quiz_count,
                    MAX(qs.created_at) as last_activity
                FROM users u
                LEFT JOIN quiz_sessions qs ON u.id = qs.user_id
                WHERE u.is_admin = false
                GROUP BY u.id, u.username, u.email
                ORDER BY quiz_count DESC, u.created_at DESC
                LIMIT 5
            `);
            console.log('✓ Query de top usuários funcionou:', topUsersResult.rows);
        } catch (err) {
            console.log('✗ Erro na query de top usuários:', err.message);
        }
        
        // Test 6: Verificar se colunas existem
        console.log('\n6. Verificando existência de colunas...');
        try {
            const usersColumns = await db.query(`
                SELECT column_name 
                FROM information_schema.columns 
                WHERE table_name = 'users' AND column_name = 'created_at'
            `);
            console.log('created_at na tabela users:', usersColumns.rows.length > 0 ? 'EXISTS' : 'NOT EXISTS');
            
            const sessionsColumns = await db.query(`
                SELECT column_name 
                FROM information_schema.columns 
                WHERE table_name = 'quiz_sessions' AND column_name = 'created_at'
            `);
            console.log('created_at na tabela quiz_sessions:', sessionsColumns.rows.length > 0 ? 'EXISTS' : 'NOT EXISTS');
            
        } catch (err) {
            console.log('✗ Erro ao verificar colunas:', err.message);
        }
        
    } catch (err) {
        console.error('Erro geral:', err.message);
    } finally {
        await db.end();
        process.exit(0);
    }
}

testQueries();
