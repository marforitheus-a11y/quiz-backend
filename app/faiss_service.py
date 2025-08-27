# Simple FAISS microservice (REST)
import faiss
import numpy as np
import json, os
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import List, Dict

INDEX_PATH = os.getenv("FAISS_INDEX_PATH", "/data/faiss/index.faiss")
META_PATH = os.getenv("FAISS_META_PATH", "/data/faiss/meta.json")
DIM = 384  # embedding dim for all-MiniLM-L6-v2

app = FastAPI(title="FAISS Service")

# in-memory index + metadata
if os.path.exists(INDEX_PATH) and os.path.exists(META_PATH):
    index = faiss.read_index(INDEX_PATH)
    with open(META_PATH, "r", encoding="utf-8") as f:
        metadata = json.load(f)
else:
    index = faiss.IndexFlatL2(DIM)
    metadata = {"ids": [], "metas": {}}

class AddDoc(BaseModel):
    id: str
    vector: List[float]
    metadata: Dict

class SearchReq(BaseModel):
    vector: List[float]
    k: int = 5

@app.post("/add")
def add_doc(doc: AddDoc):
    vec = np.array(doc.vector, dtype='float32').reshape(1, -1)
    if vec.shape[1] != DIM:
        raise HTTPException(status_code=400, detail=f"Embedding dim mismatch: expected {DIM}")
    index.add(vec)
    metadata["ids"].append(doc.id)
    metadata["metas"][doc.id] = doc.metadata
    # persist
    os.makedirs(os.path.dirname(INDEX_PATH), exist_ok=True)
    faiss.write_index(index, INDEX_PATH)
    with open(META_PATH, "w", encoding="utf-8") as f:
        json.dump(metadata, f)
    return {"status": "ok", "id": doc.id}

@app.post("/search")
def search(req: SearchReq):
    vec = np.array(req.vector, dtype='float32').reshape(1, -1)
    D, I = index.search(vec, req.k)
    results = []
    for score, idx in zip(D[0], I[0]):
        if idx == -1:
            continue
        id_ = metadata["ids"][idx]
        results.append({"id": id_, "score": float(score), "metadata": metadata["metas"].get(id_)})
    return {"results": results}

@app.get("/health")
def health():
    return {"status": "ok", "size": index.ntotal}
