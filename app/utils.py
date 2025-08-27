import os, json, uuid
from config import UPLOADS_PATH, PROMPTS_LOG
from datetime import datetime

def save_upload_file(uploaded_file_bytes, filename=None):
    os.makedirs(UPLOADS_PATH, exist_ok=True)
    if not filename:
        filename = f"{uuid.uuid4().hex}.pdf"
    path = os.path.join(UPLOADS_PATH, filename)
    with open(path, "wb") as f:
        f.write(uploaded_file_bytes)
    return path

def log_prompt(prompt, response):
    os.makedirs(os.path.dirname(PROMPTS_LOG), exist_ok=True)
    with open(PROMPTS_LOG, "a", encoding="utf-8") as f:
        f.write(f"\nTIME: {datetime.utcnow().isoformat()}\nPROMPT: {prompt}\nRESPONSE:\n{response}\n{'='*60}\n")
