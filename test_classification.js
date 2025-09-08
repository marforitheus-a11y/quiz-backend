const fetch = require('node-fetch');

async function testClassification() {
    try {
        console.log('Testando endpoint de classificação...');
        
        const response = await fetch('https://quiz-api-z4ri.onrender.com/public/final-classification', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({})
        });
        
        const responseText = await response.text();
        console.log('Status:', response.status);
        console.log('Resposta:', responseText);
        
        if (!response.ok) {
            throw new Error(`HTTP ${response.status}: ${responseText}`);
        }
        
        const data = JSON.parse(responseText);
        console.log('Dados:', JSON.stringify(data, null, 2));
        
    } catch (error) {
        console.error('Erro no teste:', error.message);
    }
}

testClassification();
