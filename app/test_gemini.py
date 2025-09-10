# Arquivo: test_gemini.py
import os
import requests
import json

# Pega as credenciais do ambiente, exatamente como sua aplicação faz
api_key = os.getenv("GEMINI_API_KEY")
# Usa a URL correta que corrigimos anteriormente
api_url = "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash-exp:generateContent"

print("--- Iniciando teste de API do Gemini ---")

if not api_key:
    print("\nERRO CRÍTICO: A variável de ambiente GEMINI_API_KEY não foi encontrada no contêiner.")
    exit()

# Imprime apenas o final da chave por segurança
print(f"Chave de API encontrada, final: ...{api_key[-4:]}")
print(f"URL da API sendo usada: {api_url}")

# Monta a URL final com a chave
final_url = f"{api_url}?key={api_key}"

headers = {"Content-Type": "application/json"}
payload = {
    "contents": [{
        "parts": [{"text": "Escreva um poema curto sobre código."}]
    }]
}

try:
    # Faz a requisição
    response = requests.post(final_url, headers=headers, data=json.dumps(payload))

    # Imprime os resultados
    print(f"\nStatus da Resposta HTTP: {response.status_code}")
    print("Corpo da Resposta:")
    print(response.text)

except Exception as e:
    print(f"\nOcorreu um erro de conexão durante a requisição: {e}")

print("\n--- Teste finalizado ---")
