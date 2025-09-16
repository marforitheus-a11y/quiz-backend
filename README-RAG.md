# Funcionalidade RAG - Sistema de Geração Especializada de Questões

## Visão Geral

A funcionalidade RAG (Retrieval-Augmented Generation) foi implementada como uma nova categoria de dificuldade que simula um sistema especializado de geração de questões baseado em dados reais de concursos públicos.

## Como Funciona

### Frontend
- Nova opção "RAG (Sistema Especializado)" adicionada nos seletores de dificuldade
- Disponível em todas as interfaces: admin.html, quiz.html e quiz-modern.html
- Estilo visual roxo (#8b5cf6) para diferenciação das outras categorias

### Backend
- Função `buildRAGPrompt()` criada para gerar prompts especializados
- Inclui exemplos de questões reais dos JSONs fornecidos (Português, Matemática, Lógica, Estatuto da Pessoa com Deficiência)
- Integração com a função `generateQuestionsFromTopic()` para processar requests RAG

### Prompt RAG Personalizado

O prompt inclui:
- Exemplos reais de questões de concursos públicos
- Instrução para manter o mesmo padrão de qualidade
- Formatação específica para questões de múltipla escolha
- Simulação de bancas reconhecidas (FGV, Instituto Consulplan, CETREDE, etc.)

## Como Usar

### No Admin
1. Acesse a área administrativa
2. Selecione "RAG (Sistema Especializado)" no campo Dificuldade
3. Informe o tema desejado
4. O sistema gerará questões baseadas nos padrões dos JSONs fornecidos

### No Quiz
1. Marque a opção "RAG" nas dificuldades
2. Configure outros parâmetros normalmente
3. Inicie o simulado

## Vantagens

1. **Economia de Custos**: Os JSONs estão incorporados no código, evitando envios repetidos
2. **Qualidade Superior**: Baseado em questões reais de concursos
3. **Padrão Profissional**: Mantém o formato e dificuldade de bancas reconhecidas
4. **Flexibilidade**: Funciona com qualquer tema solicitado

## Arquivos Modificados

### Frontend
- `quiz-frontend/admin.html`: Adicionada opção RAG nos selects
- `quiz-frontend/quiz.html`: Adicionada opção RAG e estilo
- `quiz-frontend/quiz-modern.html`: Adicionada opção RAG e estilo
- `quiz-frontend/quiz.js`: Suporte para dificuldade RAG

### Backend
- `quiz-backend/server.js`: 
  - Função `buildRAGPrompt()` 
  - Modificação em `buildPromptForDifficulty()`
  - Modificação em `generateQuestionsFromTopic()`

## Exemplos de JSONs Incluídos

O sistema inclui exemplos de 4 disciplinas:
- **Português**: Questões sobre linguagem conotativa
- **Matemática**: Cálculos geométricos complexos
- **Lógica**: Problemas de combinatória
- **Estatuto da Pessoa com Deficiência**: Legislação específica

## Uso Recomendado

A categoria RAG é ideal para:
- Geração de questões de alta qualidade
- Simulação de provas reais de concurso
- Temas específicos que precisam do padrão profissional
- Quando se busca questões mais elaboradas e contextualizadas

## Observações Técnicas

- O sistema detecta automaticamente quando `difficulty === 'rag'`
- Utiliza o mesmo pipeline de geração e validação das outras dificuldades
- Mantém compatibilidade com todas as funcionalidades existentes
- Processamento via Gemini AI com prompt especializado