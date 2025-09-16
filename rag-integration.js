// Integração da RAG no server.js existente
const ConcursoRAG = require('./rag-system');

// Inicializar RAG
const ragSystem = new ConcursoRAG();

// Nova rota para geração especializada
app.post('/admin/themes/rag-generate', authenticateToken, authorizeAdmin, async (req, res) => {
    const { themeName, questionCount, categoryId, banca, area, dificuldade } = req.body;
    
    try {
        console.log(`Gerando ${questionCount} questões especializadas via RAG...`);
        
        // Usar RAG em vez de Gemini genérica
        const questoesRAG = await ragSystem.gerarQuestaoEspecializada({
            tema: themeName,
            banca: banca || 'CESPE', // Default
            area: area || 'Direito Constitucional',
            dificuldade: dificuldade || 'medium',
            quantidade: questionCount
        });

        if (!questoesRAG || questoesRAG.length === 0) {
            // Fallback para Gemini se RAG falhar
            console.log('RAG falhou, usando fallback Gemini...');
            const geminiQuestions = await generateQuestionsFromTopic(themeName, questionCount, dificuldade);
            return await salvarQuestoes(geminiQuestions, themeName, categoryId, dificuldade, res);
        }

        // Salvar questões RAG
        await salvarQuestoes(questoesRAG, themeName, categoryId, dificuldade, res);
        
        res.status(201).json({ 
            message: `${questoesRAG.length} questões especializadas geradas com sucesso!`,
            tipo: 'RAG',
            qualidade: 'premium'
        });

    } catch (error) {
        console.error('Erro na geração RAG:', error);
        res.status(500).json({ message: 'Erro ao gerar questões especializadas' });
    }
});

// Função auxiliar para salvar questões
async function salvarQuestoes(questoes, themeName, categoryId, dificuldade, res) {
    // Ensure themes table has category_id column
    await db.query(`ALTER TABLE themes ADD COLUMN IF NOT EXISTS category_id INTEGER NULL`);
    
    const themeResult = await db.query('INSERT INTO themes (name, category_id) VALUES ($1, $2) RETURNING id', [themeName, categoryId || null]);
    const newThemeId = themeResult.rows[0].id;
    
    for (const q of questoes) {
        await db.query(`ALTER TABLE questions ADD COLUMN IF NOT EXISTS difficulty TEXT`);
        await db.query(`ALTER TABLE questions ADD COLUMN IF NOT EXISTS category_id INTEGER`);
        await db.query(`ALTER TABLE questions ADD COLUMN IF NOT EXISTS created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP`);
        
        // Validação robusta antes da inserção
        const questionText = q.question || q.enunciado || '';
        const questionOptions = q.options || q.alternativas || [];
        const questionAnswer = q.answer || q.resposta_correta || '';
        
        if (!questionText || !questionText.trim()) {
            console.error('Questão RAG inválida - texto vazio:', q);
            continue; // Pula esta questão
        }
        
        if (!Array.isArray(questionOptions) && !questionOptions) {
            console.error('Questão RAG inválida - opções vazias:', q);
            continue; // Pula esta questão
        }
        
        if (!questionAnswer || !questionAnswer.trim()) {
            console.error('Questão RAG inválida - resposta vazia:', q);
            continue; // Pula esta questão
        }
        
        console.log('Inserindo questão RAG válida:', {
            question: questionText.substring(0, 50) + '...',
            optionsType: Array.isArray(questionOptions) ? 'array' : typeof questionOptions,
            answer: questionAnswer.substring(0, 20) + '...'
        });
        
        const optionsToSave = Array.isArray(questionOptions) ? questionOptions : JSON.stringify(questionOptions);
        
        await db.query(
            'INSERT INTO questions (theme_id, question, options, answer, difficulty, category_id) VALUES ($1, $2, $3, $4, $5, $6)',
            [newThemeId, questionText.trim(), optionsToSave, questionAnswer.trim(), dificuldade, categoryId || null]
        );
    }
}

// Rota para alimentar a base de conhecimento
app.post('/admin/rag/index-prova', authenticateToken, authorizeAdmin, upload.single('provaFile'), async (req, res) => {
    const { banca, orgao, area, ano } = req.body;
    const file = req.file;
    
    if (!file) {
        return res.status(400).json({ message: 'Arquivo de prova é obrigatório' });
    }

    try {
        // Processar PDF da prova
        const dataBuffer = fs.readFileSync(file.path);
        const data = await pdfParse(dataBuffer);
        
        // Extrair questões usando regex/AI
        const questoesExtraidas = await extrairQuestoesDeProva(data.text, { banca, orgao, area, ano });
        
        // Indexar cada questão na RAG
        for (const questao of questoesExtraidas) {
            await ragSystem.indexarProva({
                id: `${banca}_${orgao}_${ano}_${questao.numero}`,
                banca,
                orgao,
                area,
                ano,
                questao
            });
        }

        res.status(200).json({ 
            message: `${questoesExtraidas.length} questões indexadas com sucesso!`,
            base_conhecimento: 'atualizada'
        });

    } catch (error) {
        console.error('Erro ao indexar prova:', error);
        res.status(500).json({ message: 'Erro ao processar prova' });
    } finally {
        if (file && file.path) {
            fs.unlinkSync(file.path);
        }
    }
});

// Função para extrair questões de PDF
async function extrairQuestoesDeProva(texto, metadata) {
    // Usar regex para identificar padrões de questões
    const questoesRegex = /(\d+)\.\s*(.*?)(?=\d+\.|$)/gs;
    const questoes = [];
    
    let match;
    while ((match = questoesRegex.exec(texto)) !== null) {
        const [, numero, conteudo] = match;
        
        // Extrair alternativas
        const alternativasRegex = /[A-E]\)\s*([^A-E]+?)(?=[A-E]\)|$)/g;
        const alternativas = [];
        let altMatch;
        
        while ((altMatch = alternativasRegex.exec(conteudo)) !== null) {
            alternativas.push(altMatch[1].trim());
        }

        if (alternativas.length >= 4) {
            questoes.push({
                numero: parseInt(numero),
                enunciado: conteudo.split('A)')[0].trim(),
                alternativas: alternativas,
                // Resposta precisa ser extraída do gabarito separadamente
                resposta_correta: null,
                dificuldade: 'medium'
            });
        }
    }
    
    return questoes;
}
