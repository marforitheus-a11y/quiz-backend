const https = require('https');

function testMetricsEndpoint() {
    console.log('Testando endpoint de métricas corrigido...');
    console.log('Aguardando deploy automático na Render...\n');
    
    const url = 'https://quiz-api-z4ri.onrender.com/admin/dashboard/metrics';
    
    // Vamos tentar algumas vezes, pois o deploy pode levar um tempo
    let attempts = 0;
    const maxAttempts = 5;
    
    function attemptRequest() {
        attempts++;
        console.log(`Tentativa ${attempts}/${maxAttempts}...`);
        
        https.get(url, (res) => {
            let data = '';
            
            res.on('data', (chunk) => {
                data += chunk;
            });
            
            res.on('end', () => {
                console.log('Status:', res.statusCode);
                
                if (res.statusCode === 200) {
                    console.log('✓ Endpoint de métricas funcionando!');
                    console.log('\nPrimeiros caracteres da resposta:');
                    console.log(data.substring(0, 200) + '...');
                } else if (res.statusCode === 401) {
                    console.log('✗ Erro 401: Não autorizado (esperado sem token)');
                } else if (res.statusCode === 500) {
                    console.log('✗ Ainda há erro 500:');
                    console.log(data);
                    
                    if (attempts < maxAttempts) {
                        console.log(`\nAguardando 30 segundos para próxima tentativa...`);
                        setTimeout(attemptRequest, 30000);
                    } else {
                        console.log('\nTodas as tentativas falharam. Pode ser necessário mais tempo para deploy.');
                    }
                } else {
                    console.log('Status inesperado:', res.statusCode);
                    console.log(data);
                }
            });
        }).on('error', (err) => {
            console.error('Erro na requisição:', err.message);
            
            if (attempts < maxAttempts) {
                console.log(`\nAguardando 30 segundos para próxima tentativa...`);
                setTimeout(attemptRequest, 30000);
            }
        });
    }
    
    attemptRequest();
}

// Começar o teste
testMetricsEndpoint();
