const axios = require('axios');

async function checkCurrentStats() {
    try {
        console.log('Verificando estatísticas atuais...');
        
        const response = await axios.get('https://quiz-api-z4ri.onrender.com/public/diagnose-categories');
        
        console.log('Status:', response.status);
        console.log('Diagnóstico atual:', JSON.stringify(response.data, null, 2));
        
    } catch (error) {
        console.error('Erro ao verificar:', error.response?.data || error.message);
    }
}

checkCurrentStats();
