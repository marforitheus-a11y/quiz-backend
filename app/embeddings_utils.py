from sentence_transformers import SentenceTransformer
import numpy as np

_model = None
def get_model():
    global _model
    if _model is None:
        _model = SentenceTransformer("all-MiniLM-L6-v2")
    return _model

def encode_texts(texts):
    """
    Return list of vectors (python lists) for given texts.
    """
    m = get_model()
    vectors = m.encode(texts, show_progress_bar=False, convert_to_numpy=True)
    return [v.tolist() for v in vectors]
