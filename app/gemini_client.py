import requests
import json
import os
from config import GEMINI_API_KEY, GEMINI_API_URL, MAX_OUTPUT_TOKENS, TEMPERATURE

def ask_gemini(prompt: str) -> str:
    """
    Envia um prompt para a API do Gemini e retorna a resposta em texto.
    """
    # --- ALTERAÇÃO APLICADA AQUI ---
    # Adicionamos .strip() para remover espaços/caracteres invisíveis da chave
    api_key = os.getenv("GEMINI_API_KEY", "").strip()

    if not api_key:
        raise ValueError("A chave de API do Gemini (GEMINI_API_KEY) não foi encontrada ou está vazia.")
    
    final_url = f"{GEMINI_API_URL}?key={api_key}"
    
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
        response = requests.post(final_url, headers=headers, data=json.dumps(payload), timeout=600)
        response.raise_for_status() 
        data = response.json()
        text_response = data["candidates"][0]["content"]["parts"][0]["text"]
        return text_response
        
    except requests.exceptions.HTTPError as http_err:
        raise RuntimeError(f"Erro na API do Gemini {http_err.response.status_code}: {http_err.response.text}")
    except Exception as e:
        raise RuntimeError(f"Ocorreu um erro inesperado ao contatar o Gemini: {e}")