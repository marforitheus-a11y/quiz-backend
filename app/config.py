import os
from dotenv import load_dotenv
load_dotenv()

# --- Configurações de API e Serviços ---
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
GEMINI_API_URL = os.getenv("GEMINI_API_URL")

GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")
GITHUB_HOST = os.getenv("GITHUB_HOST", "github.com")
REPO_NAME = os.getenv("REPO_NAME")

REDIS_URL = os.getenv("REDIS_URL", "redis://redis:6379/0")


# --- Configuração do Banco de Dados (CORRIGIDA) ---
# Removemos as variáveis POSTGRES_* individuais.
# Agora, lemos a URL de conexão completa diretamente do ambiente.
# Esta é a única fonte de verdade para a conexão com o banco.
DATABASE_URL = os.getenv("DATABASE_URL")

# Verificação para garantir que a variável foi carregada
if not DATABASE_URL:
    raise ValueError("A variável de ambiente DATABASE_URL não foi definida! Verifique seu arquivo .env.")


# --- Configurações de Caminhos e Armazenamento ---
FAISS_INDEX_PATH = os.getenv("FAISS_INDEX_PATH", "/data/faiss/index.faiss")
FAISS_META_PATH = os.getenv("FAISS_META_PATH", "/data/faiss/meta.json")

PROJECT_CLONE_PATH = os.getenv("PROJECT_CLONE_PATH", "/data/project_clone")
UPLOADS_PATH = os.getenv("UPLOADS_PATH", "/data/uploads")
PROMPTS_LOG = os.getenv("PROMPTS_LOG", "/data/prompts_history/log.txt")


# --- Limites e Parâmetros ---
MAX_OUTPUT_TOKENS = int(os.getenv("MAX_OUTPUT_TOKENS", 1500))
TEMPERATURE = float(os.getenv("TEMPERATURE", 0.2))