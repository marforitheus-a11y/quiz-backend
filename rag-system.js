// RAG System para Questões de Concurso
const { OpenAI } = require('openai');
const { Pinecone } = require('@pinecone-database/pinecone');

class ConcursoRAG {
    constructor() {
        this.openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });
        this.pinecone = new Pinecone({ apiKey: process.env.PINECONE_API_KEY });
        this.index = this.pinecone.index('concursos-knowledge');
    }

    // 1. Processar e indexar provas existentes
    async indexarProva(prova) {
        try {
            // Criar embedding para cada questão
            const embedding = await this.openai.embeddings.create({
                model: "text-embedding-3-small",
                input: `${prova.area} ${prova.banca} ${prova.questao.enunciado}`,
            });

            // Salvar no vector database
            await this.index.upsert([{
                id: `questao_${prova.id}`,
                values: embedding.data[0].embedding,
                metadata: {
                    banca: prova.banca,
                    orgao: prova.orgao,
                    area: prova.area,
                    dificuldade: prova.questao.dificuldade,
                    enunciado: prova.questao.enunciado,
                    alternativas: prova.questao.alternativas,
                    resposta: prova.questao.resposta_correta,
                    padrao_redacao: this.extrairPadraoRedacao(prova.questao)
                }
            }]);

            console.log(`Questão indexada: ${prova.id}`);
        } catch (error) {
            console.error('Erro ao indexar questão:', error);
        }
    }

    // 2. Buscar questões similares para contexto
    async buscarContexto(tema, banca, area, quantidade = 5) {
        const queryEmbedding = await this.openai.embeddings.create({
            model: "text-embedding-3-small",
            input: `${area} ${banca} ${tema}`,
        });

        const results = await this.index.query({
            vector: queryEmbedding.data[0].embedding,
            topK: quantidade,
            filter: {
                banca: { "$eq": banca },
                area: { "$eq": area }
            },
            includeMetadata: true
        });

        return results.matches.map(match => match.metadata);
    }

    // 3. Gerar questão usando contexto RAG
    async gerarQuestaoEspecializada(params) {
        const { tema, banca, area, dificuldade, quantidade = 1 } = params;
        
        // Buscar contexto relevante
        const contexto = await this.buscarContexto(tema, banca, area);
        
        // Criar prompt especializado
        const prompt = this.criarPromptEspecializado(tema, banca, area, dificuldade, contexto);
        
        // Gerar questão
        const response = await this.openai.chat.completions.create({
            model: "gpt-4o-mini",
            messages: [
                {
                    role: "system",
                    content: "Você é um especialista em elaboração de questões para concursos públicos brasileiros."
                },
                {
                    role: "user",
                    content: prompt
                }
            ],
            temperature: 0.7,
            max_tokens: 2000
        });

        return this.processarResposta(response.choices[0].message.content);
    }

    criarPromptEspecializado(tema, banca, area, dificuldade, contexto) {
        const exemplos = contexto.map(q => `
EXEMPLO ${contexto.indexOf(q) + 1}:
Enunciado: ${q.enunciado}
Alternativas: ${q.alternativas.join('; ')}
Resposta: ${q.resposta}
Padrão: ${q.padrao_redacao}
        `).join('\n');

        return `
CONTEXTO: Elabore ${quantidade} questão(s) de concurso público para ${banca} na área de ${area}.

TEMA ESPECÍFICO: ${tema}
DIFICULDADE: ${dificuldade}

PADRÕES DA BANCA ${banca}:
${exemplos}

INSTRUÇÕES:
1. Siga EXATAMENTE o padrão de redação da ${banca}
2. Use terminologia jurídica precisa para ${area}
3. Crie alternativas plausíveis mas com apenas uma correta
4. Dificuldade ${dificuldade}: ${this.getInstrucoesDificuldade(dificuldade)}
5. RESPONDA APENAS em JSON: [{"question":"...","options":["..."],"answer":"...","justificativa":"..."}]

IMPORTANTE: A questão deve ser indistinguível de uma questão real da ${banca}.
        `;
    }

    getInstrucoesDificuldade(nivel) {
        const instrucoes = {
            'easy': 'Conceitos básicos, aplicação direta da lei',
            'medium': 'Interpretação de situações práticas, correlação entre institutos',
            'hard': 'Casos complexos, pegadinhas sutis, jurisprudência específica'
        };
        return instrucoes[nivel] || instrucoes['medium'];
    }

    extrairPadraoRedacao(questao) {
        // Analisar padrões da banca (linguagem, estrutura, etc.)
        const padroes = [];
        
        if (questao.enunciado.includes('Acerca de')) padroes.push('abertura_acerca');
        if (questao.enunciado.includes('é correto afirmar')) padroes.push('conclusao_afirmar');
        if (questao.enunciado.includes('EXCETO')) padroes.push('excecao');
        
        return padroes.join(',');
    }

    processarResposta(resposta) {
        try {
            const jsonMatch = resposta.match(/\[[\s\S]*\]/);
            if (jsonMatch) {
                return JSON.parse(jsonMatch[0]);
            }
            throw new Error('Formato JSON inválido');
        } catch (error) {
            console.error('Erro ao processar resposta:', error);
            return null;
        }
    }
}

module.exports = ConcursoRAG;
