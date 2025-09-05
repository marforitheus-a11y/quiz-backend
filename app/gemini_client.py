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
        raise ValueError("A chave de API do Gemini (GEMINI_API_KEY) não foi encontrada.")

    final_url = f"{GEMINI_API_URL}?key={api_key}"

    payload = {
        "prompt": prompt,
        "max_output_tokens": MAX_OUTPUT_TOKENS,
        "temperature": TEMPERATURE
    }

    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {api_key}"
    }

    response = requests.post(final_url, headers=headers, data=json.dumps(payload))

    if response.status_code != 200:
        raise Exception(f"Erro na API Gemini: {response.status_code} - {response.text}")

    data = response.json()
    return data.get("text", "")
