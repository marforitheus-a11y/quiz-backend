import requests, json
from config import GEMINI_API_KEY, GEMINI_API_URL, MAX_OUTPUT_TOKENS, TEMPERATURE

HEADERS = {"Authorization": f"Bearer {GEMINI_API_KEY}", "Content-Type": "application/json"}

def ask_gemini(prompt: str, context: str = "") -> str:
    """
    Send prompt+context to Gemini Pro. Returns string output.
    NOTE: adapt GEMINI_API_URL/payload if Google changes schema.
    """
    full_prompt = (context + "\n\n" if context else "") + prompt
    payload = {
        "prompt": full_prompt,
        "temperature": TEMPERATURE,
        "max_output_tokens": MAX_OUTPUT_TOKENS
    }
    r = requests.post(GEMINI_API_URL, headers=HEADERS, data=json.dumps(payload), timeout=600)
    if r.status_code != 200:
        raise RuntimeError(f"Gemini API error {r.status_code}: {r.text}")
    data = r.json()
    # expected shape: { "candidates": [{"content":"..."}], ... }
    return data.get("candidates", [{}])[0].get("content", "")
