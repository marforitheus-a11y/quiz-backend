const https = require('https');

function testProductionEndpoint() {
    console.log('Testando endpoint de produção...');
    
    // URL de produção
    const url = 'https://quiz-api-z4ri.onrender.com/admin/dashboard/simple';
    
    // Vamos primeiro testar o endpoint simples
    https.get(url, (res) => {
        let data = '';
        
        res.on('data', (chunk) => {
            data += chunk;
        });
        
        res.on('end', () => {
            console.log('Status:', res.statusCode);
            console.log('Response:', data);
            
            if (res.statusCode === 200) {
                console.log('✓ Endpoint simples funcionando');
                testMetricsEndpoint();
            } else {
                console.log('✗ Erro no endpoint simples');
            }
        });
    }).on('error', (err) => {
        console.error('Erro na requisição:', err.message);
    });
}

function testMetricsEndpoint() {
    console.log('\nTestando endpoint de métricas...');
    
    const url = 'https://quiz-api-z4ri.onrender.com/admin/dashboard/metrics';
    
    https.get(url, (res) => {
        let data = '';
        
        res.on('data', (chunk) => {
            data += chunk;
        });
        
        res.on('end', () => {
            console.log('Status:', res.statusCode);
            console.log('Response:', data);
            
            if (res.statusCode === 200) {
                console.log('✓ Endpoint de métricas funcionando');
            } else {
                console.log('✗ Erro no endpoint de métricas');
            }
        });
    }).on('error', (err) => {
        console.error('Erro na requisição:', err.message);
    });
}

testProductionEndpoint();
