import requests
import json
import os
from config import GEMINI_API_KEY, GEMINI_API_URL, MAX_OUTPUT_TOKENS, TEMPERATURE

def ask_gemini(prompt: str) -> str:
    """
    Envia um prompt para a API do Gemini e retorna a resposta em texto.
    """
    if not GEMINI_API_KEY:
        raise ValueError("A chave de API do Gemini (GEMINI_API_KEY) não foi encontrada no ambiente.")
    
    # Monta a URL final com a chave de API como parâmetro
    final_url = f"{GEMINI_API_URL}?key={GEMINI_API_KEY}"
    
    # Usa o formato de payload (corpo da requisição) correto e atual
    payload = {
        "contents": [{
            "parts": [{"text": prompt}]
        }],
        "generationConfig": {
            "temperature": TEMPERATURE,
            "maxOutputTokens": MAX_OUTPUT_TOKENS
        }
    }
    
    headers = {"Content-Type": "application/json"}

    try:
        # Faz a requisição POST
        response = requests.post(final_url, headers=headers, data=json.dumps(payload), timeout=600)
        
        # Levanta um erro se a resposta não for bem-sucedida
        response.raise_for_status() 
        
        data = response.json()
        
        # Extrai o texto da resposta no formato novo e correto
        text_response = data["candidates"][0]["content"]["parts"][0]["text"]
        return text_response
        
    except requests.exceptions.HTTPError as http_err:
        # Erro HTTP retornado pela API (ex: 400 Bad Request, 401 Unauthorized, etc.)
        raise RuntimeError(f"Erro na API do Gemini {http_err.response.status_code}: {http_err.response.text}")
    except Exception as e:
        # Outros erros (ex: rede, timeout)
        raise RuntimeError(f"Ocorreu um erro inesperado ao contatar o Gemini: {e}")