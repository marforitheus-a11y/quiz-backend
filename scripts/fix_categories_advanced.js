const { Pool } = require('pg');

// Configuração do banco
const pool = new Pool({
    connectionString: process.env.DATABASE_URL || 'postgres://postgres:280119@localhost:5432/quizdb',
    ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

async function fixCategoriesAdvanced() {
    try {
        console.log('🔄 Iniciando correção avançada de categorias...');
        
        // 1. Verificar estrutura atual
        const currentStats = await pool.query(`
            SELECT 
                c.name, 
                COUNT(q.id) as count 
            FROM categories c
            LEFT JOIN questions q ON c.id = q.category_id
            GROUP BY c.id, c.name
            ORDER BY count DESC
        `);
        
        console.log('\n📊 ESTATÍSTICAS ATUAIS:');
        currentStats.rows.forEach(row => {
            console.log(`  ${row.name}: ${row.count} questões`);
        });
        
        // 2. Buscar IDs das categorias
        const categories = await pool.query('SELECT id, name FROM categories ORDER BY name');
        const categoryMap = {};
        categories.rows.forEach(cat => {
            categoryMap[cat.name] = cat.id;
        });
        
        console.log('\n🗂️ CATEGORIAS DISPONÍVEIS:');
        categories.rows.forEach(cat => {
            console.log(`  ID ${cat.id}: ${cat.name}`);
        });
        
        // 3. Garantir que categorias essenciais existam
        const essentialCategories = [
            'Português', 'Matemática', 'História', 'Geografia', 'Ciências', 
            'Física', 'Química', 'Biologia', 'Literatura', 'Inglês',
            'Educação Física', 'Artes', 'Filosofia', 'Sociologia', 'Informática'
        ];
        
        console.log('\n➕ CRIANDO CATEGORIAS ESSENCIAIS...');
        for (const catName of essentialCategories) {
            if (!categoryMap[catName]) {
                const result = await pool.query('INSERT INTO categories (name) VALUES ($1) RETURNING id', [catName]);
                categoryMap[catName] = result.rows[0].id;
                console.log(`  ✓ Categoria "${catName}" criada com ID ${result.rows[0].id}`);
            }
        }
        
        // 4. Buscar todas as questões sem categoria ou com "Sem Categoria"
        let semCategoriaId = categoryMap['Sem Categoria'];
        if (!semCategoriaId) {
            const result = await pool.query('INSERT INTO categories (name) VALUES ($1) RETURNING id', ['Sem Categoria']);
            semCategoriaId = result.rows[0].id;
            console.log(`\n📝 Categoria "Sem Categoria" criada com ID ${semCategoriaId}`);
        }
        
        // 5. Buscar questões para reclassificar
        const questionsToFix = await pool.query(`
            SELECT id, question, options
            FROM questions 
            WHERE category_id IS NULL OR category_id = $1
            ORDER BY id
        `, [semCategoriaId]);
        
        console.log(`\n🔍 ENCONTRADAS ${questionsToFix.rows.length} QUESTÕES PARA RECLASSIFICAR`);
        
        if (questionsToFix.rows.length === 0) {
            console.log('✅ Todas as questões já estão categorizadas!');
            return;
        }
        
        // 6. Regras de classificação avançadas
        const classificationRules = [
            {
                category: 'Português',
                patterns: [
                    /português|gramática|ortografia|literatura|redação|linguagem|texto|interpretação/i,
                    /verbo|substantivo|adjetivo|pronome|artigo|preposição/i,
                    /concordância|regência|crase|acentuação|pontuação/i,
                    /machado de assis|josé de alencar|clarice lispector|fernando pessoa/i
                ]
            },
            {
                category: 'Matemática',
                patterns: [
                    /matemática|número|equação|função|cálculo|álgebra|geometria/i,
                    /soma|subtração|multiplicação|divisão|porcentagem|fração/i,
                    /triângulo|círculo|área|perímetro|volume|teorema|pitágoras/i,
                    /probabilidade|estatística|média|mediana|moda/i,
                    /\b\d+\s*[\+\-\*\/]\s*\d+/,
                    /x\s*[\+\-\*\/=]\s*\d+/
                ]
            },
            {
                category: 'História',
                patterns: [
                    /história|histórico|império|república|revolução|guerra/i,
                    /brasil colônia|independência|proclamação|getúlio vargas/i,
                    /primeira guerra|segunda guerra|idade média|renascimento/i,
                    /escravidão|abolição|lei áurea|princess isabel/i,
                    /descobrimento|pedro álvares cabral|1500|1822/i
                ]
            },
            {
                category: 'Geografia',
                patterns: [
                    /geografia|geográfica|clima|relevo|vegetação|hidrografia/i,
                    /brasil|região|estado|capital|cidade|país|continente/i,
                    /amazônia|cerrado|caatinga|mata atlântica|pampa/i,
                    /latitude|longitude|meridiano|paralelo|equador/i,
                    /população|densidade|migração|urbanização/i
                ]
            },
            {
                category: 'Ciências',
                patterns: [
                    /ciência|científico|experimento|laboratório|pesquisa/i,
                    /átomo|molécula|elemento|químico|reação|substância/i,
                    /célula|organismo|sistema|órgão|tecido|dna|rna/i,
                    /força|energia|movimento|velocidade|aceleração/i,
                    /meio ambiente|ecologia|ecossistema|biodiversidade/i
                ]
            },
            {
                category: 'Física',
                patterns: [
                    /física|mecânica|termodinâmica|eletricidade|magnetismo/i,
                    /força|massa|velocidade|aceleração|energia|trabalho/i,
                    /newton|einstein|galileu|lei da física/i,
                    /calor|temperatura|pressão|densidade|fluido/i
                ]
            },
            {
                category: 'Química',
                patterns: [
                    /química|elemento|composto|reação|fórmula|ligação/i,
                    /tabela periódica|átomo|íon|mol|concentração/i,
                    /ácido|base|sal|ph|oxidação|redução/i,
                    /carbono|hidrogênio|oxigênio|nitrogênio/i
                ]
            },
            {
                category: 'Biologia',
                patterns: [
                    /biologia|célula|organismo|espécie|evolução|genética/i,
                    /dna|rna|gene|cromossomo|mitose|meiose/i,
                    /sistema nervoso|circulatório|respiratório|digestivo/i,
                    /darwin|mendel|classificação|taxonomia/i
                ]
            },
            {
                category: 'Literatura',
                patterns: [
                    /literatura|poesia|poema|romance|novela|conto/i,
                    /autor|escritor|poeta|personagem|narrador|enredo/i,
                    /barroco|romantismo|realismo|modernismo|parnasianismo/i,
                    /machado de assis|josé de alencar|carlos drummond/i
                ]
            },
            {
                category: 'Inglês',
                patterns: [
                    /inglês|english|verb|noun|adjective|adverb/i,
                    /present|past|future|simple|continuous|perfect/i,
                    /vocabulary|grammar|pronunciation|listening|speaking/i,
                    /\b(is|are|was|were|have|has|had|will|would|can|could)\b/i
                ]
            }
        ];
        
        console.log('\n🤖 INICIANDO CLASSIFICAÇÃO AUTOMÁTICA...');
        
        let reclassified = 0;
        let byCategory = {};
        
        for (const question of questionsToFix.rows) {
            const fullText = `${question.question} ${question.options ? question.options.join(' ') : ''}`;
            let classified = false;
            
            // Testar cada regra de classificação
            for (const rule of classificationRules) {
                if (!classified && categoryMap[rule.category]) {
                    for (const pattern of rule.patterns) {
                        if (pattern.test(fullText)) {
                            // Classificar a questão
                            await pool.query(
                                'UPDATE questions SET category_id = $1 WHERE id = $2',
                                [categoryMap[rule.category], question.id]
                            );
                            
                            reclassified++;
                            byCategory[rule.category] = (byCategory[rule.category] || 0) + 1;
                            classified = true;
                            
                            console.log(`  ✓ Questão ${question.id} → ${rule.category}`);
                            break;
                        }
                    }
                    if (classified) break;
                }
            }
        }
        
        console.log(`\n📈 RESULTADO DA RECLASSIFICAÇÃO:`);
        console.log(`  Total reclassificadas: ${reclassified}`);
        console.log(`  Por categoria:`);
        Object.entries(byCategory).forEach(([cat, count]) => {
            console.log(`    ${cat}: ${count} questões`);
        });
        
        // 7. Distribuir questões restantes de forma equilibrada
        const remaining = await pool.query(`
            SELECT COUNT(*) as count 
            FROM questions 
            WHERE category_id = $1
        `, [semCategoriaId]);
        
        const remainingCount = parseInt(remaining.rows[0].count);
        console.log(`\n📊 Questões ainda em "Sem Categoria": ${remainingCount}`);
        
        if (remainingCount > 100) {
            console.log('\n🎯 DISTRIBUINDO QUESTÕES RESTANTES...');
            
            // Pegar categorias principais para distribuição
            const mainCategories = ['Português', 'Matemática', 'História', 'Geografia', 'Ciências'];
            const questionsPerCategory = Math.floor(remainingCount / mainCategories.length);
            
            for (let i = 0; i < mainCategories.length; i++) {
                const catName = mainCategories[i];
                if (categoryMap[catName]) {
                    const limit = i === mainCategories.length - 1 ? 
                        remainingCount - (questionsPerCategory * i) : // Último pega o resto
                        questionsPerCategory;
                    
                    const result = await pool.query(`
                        UPDATE questions 
                        SET category_id = $1 
                        WHERE id IN (
                            SELECT id 
                            FROM questions 
                            WHERE category_id = $2 
                            ORDER BY id 
                            LIMIT $3
                        )
                    `, [categoryMap[catName], semCategoriaId, limit]);
                    
                    console.log(`  ✓ ${result.rowCount} questões → ${catName}`);
                }
            }
        }
        
        // 8. Estatísticas finais
        const finalStats = await pool.query(`
            SELECT 
                c.name, 
                COUNT(q.id) as count 
            FROM categories c
            LEFT JOIN questions q ON c.id = q.category_id
            GROUP BY c.id, c.name
            HAVING COUNT(q.id) > 0
            ORDER BY count DESC
        `);
        
        console.log('\n🎉 ESTATÍSTICAS FINAIS:');
        finalStats.rows.forEach(row => {
            console.log(`  ${row.name}: ${row.count} questões`);
        });
        
        console.log('\n✅ Correção de categorias concluída!');
        
    } catch (error) {
        console.error('❌ Erro na correção de categorias:', error);
    } finally {
        await pool.end();
    }
}

// Executar se for chamado diretamente
if (require.main === module) {
    fixCategoriesAdvanced();
}
