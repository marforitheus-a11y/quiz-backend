const axios = require('axios');

async function finalCorrection() {
    try {
        console.log('Iniciando correção final - classificando questões sem categoria...');
        
        // Primeiro vamos reclassificar todas as questões que estão como "Sem Categoria"
        const response = await axios.post('https://quiz-api-z4ri.onrender.com/public/final-classification');
        
        console.log('Status:', response.status);
        console.log('Resultado:', JSON.stringify(response.data, null, 2));
        
        if (response.data.success) {
            console.log('\n✅ CORREÇÃO FINAL CONCLUÍDA COM SUCESSO!');
            console.log('- Questões reclassificadas usando palavras-chave');
            console.log('- Dashboard agora mostra distribuição real das categorias');
        }
        
    } catch (error) {
        console.error('Erro ao executar correção:', error.response?.data || error.message);
    }
}

finalCorrection();
