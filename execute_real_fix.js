const axios = require('axios');

async function executeRealFix() {
    try {
        console.log('Executando correção com categorias reais...');
        
        const response = await axios.post('https://quiz-api-z4ri.onrender.com/public/fix-real-categories');
        
        console.log('Status:', response.status);
        console.log('Resultado:', response.data);
        
        if (response.data.success) {
            console.log('\n✅ CORREÇÃO CONCLUÍDA COM SUCESSO!');
            console.log('- Categorias artificiais removidas');
            console.log('- Questões reclassificadas com categorias originais');
            console.log('- Dashboard agora mostra apenas dados autênticos');
        }
        
    } catch (error) {
        console.error('Erro ao executar correção:', error.response?.data || error.message);
    }
}

executeRealFix();
