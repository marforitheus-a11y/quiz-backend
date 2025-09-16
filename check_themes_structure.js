// Script para verificar a estrutura real da tabela themes
const db = require('./db');

async function checkThemesStructure() {
    try {
        console.log('🔍 Verificando estrutura da tabela themes...');
        
        // 1. Verificar se a tabela themes existe
        const tablesResult = await db.query(`
            SELECT table_name 
            FROM information_schema.tables 
            WHERE table_schema = 'public' AND table_name = 'themes'
        `);
        
        if (tablesResult.rows.length === 0) {
            console.log('❌ Tabela "themes" não encontrada!');
            return;
        }
        
        console.log('✅ Tabela "themes" encontrada');
        
        // 2. Verificar estrutura das colunas
        const columnsResult = await db.query(`
            SELECT column_name, data_type, is_nullable, column_default
            FROM information_schema.columns 
            WHERE table_schema = 'public' AND table_name = 'themes'
            ORDER BY ordinal_position
        `);
        
        console.log('\n📋 Estrutura da tabela themes:');
        console.log('=================================');
        columnsResult.rows.forEach(col => {
            console.log(`   • ${col.column_name} (${col.data_type}) - Nullable: ${col.is_nullable}`);
        });
        
        // 3. Verificar alguns dados de exemplo
        const sampleResult = await db.query('SELECT * FROM themes LIMIT 3');
        console.log('\n📄 Dados de exemplo:');
        console.log('====================');
        if (sampleResult.rows.length > 0) {
            console.log('Colunas disponíveis:', Object.keys(sampleResult.rows[0]));
            sampleResult.rows.forEach((row, index) => {
                console.log(`\nTema ${index + 1}:`, JSON.stringify(row, null, 2));
            });
        } else {
            console.log('❌ Nenhum dado encontrado na tabela themes');
        }
        
        // 4. Contar total de temas
        const countResult = await db.query('SELECT COUNT(*) as total FROM themes');
        console.log(`\n📊 Total de temas: ${countResult.rows[0].total}`);
        
    } catch (err) {
        console.error('❌ Erro ao verificar estrutura:', err.message);
        console.error('Stack:', err.stack);
    } finally {
        process.exit(0);
    }
}

checkThemesStructure();
