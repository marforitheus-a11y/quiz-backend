# Celery tasks: process PDFs, create embeddings, call Gemini to generate Qs
from celery import Celery
import os, json, requests
from config import REDIS_URL, FAISS_INDEX_PATH, FAISS_META_PATH, GEMINI_API_URL, GEMINI_API_KEY
from embeddings_utils import encode_texts
from utils import log_prompt
from db_models import SessionLocal, Question, init_db
from pypdf import PdfReader

app = Celery('tasks', broker=os.getenv("REDIS_URL", REDIS_URL))

FAISS_SERVICE_URL = "http://faiss:8003"

init_db()

@app.task(bind=True)
def process_pdf(self, file_path, theme):
    # 1) Extract text
    texts = []
    try:
        reader = PdfReader(file_path)
        for p in reader.pages:
            txt = p.extract_text()
            if txt:
                texts.append(txt.strip())
    except Exception as e:
        raise RuntimeError("PDF extraction failed: " + str(e))

    # 2) chunk text into smaller pieces (approx 800 chars)
    chunks = []
    for t in texts:
        s = t
        while len(s) > 800:
            chunk = s[:800]
            # try cut at sentence end
            cut = chunk.rfind('.')
            if cut > 100:
                chunk = chunk[:cut+1]
            chunks.append(chunk.strip())
            s = s[len(chunk):].strip()
        if s:
            chunks.append(s.strip())

    # 3) compute embeddings
    vectors = encode_texts(chunks)

    # 4) add to FAISS
    for i, vec in enumerate(vectors):
        doc_id = f"{os.path.basename(file_path)}_chunk_{i}"
        payload = {"id": doc_id, "vector": vec, "metadata": {"theme": theme, "source": file_path, "chunk_index": i, "text": chunks[i][:1000]}}
        r = requests.post(f"{FAISS_SERVICE_URL}/add", json=payload, timeout=60)
        if r.status_code != 200:
            raise RuntimeError("FAISS add failed: " + r.text)

    # 5) Ask Gemini to generate questions using concatenated chunks as context
    # Compose a prompt:
    combined_context = "\n\n".join(chunks[:10])  # limit context
    prompt = f"Você é um especialista em criar questões estilo concurso. Usando o texto abaixo gere 10 questões de múltipla escolha (A-E) com uma resposta correta marcada e explique brevemente a justificativa. Tema: {theme}\n\nContexto:\n{combined_context}\n\nSaia apenas em JSON: [{'{'}\"pergunta\": \"...\", \"alternativas\": [\"...\"], \"resposta\": \"A\", \"justificativa\":\"...\"{'}'}, ...]"
    headers = {"Authorization": f"Bearer {GEMINI_API_KEY}", "Content-Type": "application/json"}
    payload = {"prompt": prompt, "temperature": 0.2, "max_output_tokens": 1200}
    r = requests.post(GEMINI_API_URL, headers=headers, json=payload, timeout=600)
    if r.status_code != 200:
        raise RuntimeError("Gemini generation failed: " + r.text)
    data = r.json()
    gen_text = data.get("candidates", [{}])[0].get("content", "")
    log_prompt(prompt, gen_text)

    # 6) parse JSON from Gemini (best effort)
    try:
        items = json.loads(gen_text)
    except Exception as e:
        # fallback: try to extract JSON substring
        import re
        m = re.search(r'(\[.*\])', gen_text, re.S)
        if m:
            items = json.loads(m.group(1))
        else:
            raise RuntimeError("Failed to parse Gemini response as JSON")

    # 7) save questions to DB
    db = SessionLocal()
    for it in items:
        q = Question(
            theme=theme,
            prompt=it.get("pergunta") or it.get("question") or "",
            alternatives=it.get("alternativas") or it.get("choices") or [],
            answer=it.get("resposta") or it.get("answer"),
            source=file_path
        )
        db.add(q)
    db.commit()
    db.close()
    return {"status": "ok", "added": len(items)}
