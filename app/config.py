import os
from dotenv import load_dotenv
load_dotenv()

GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
GEMINI_API_URL = os.getenv("GEMINI_API_URL")

GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")
GITHUB_HOST = os.getenv("GITHUB_HOST", "github.com")
REPO_NAME = os.getenv("REPO_NAME")

REDIS_URL = os.getenv("REDIS_URL", "redis://redis:6379/0")

POSTGRES_USER = os.getenv("POSTGRES_USER", "sa")
POSTGRES_PASSWORD = os.getenv("POSTGRES_PASSWORD", "sa_password")
POSTGRES_DB = os.getenv("POSTGRES_DB", "ai_assistant")
POSTGRES_PORT = int(os.getenv("POSTGRES_PORT", 5432))
POSTGRES_HOST = os.getenv("POSTGRES_HOST", "postgres")
DATABASE_URL = f"postgresql://{POSTGRES_USER}:{POSTGRES_PASSWORD}@{POSTGRES_HOST}:{POSTGRES_PORT}/{POSTGRES_DB}"

FAISS_INDEX_PATH = os.getenv("FAISS_INDEX_PATH", "/data/faiss/index.faiss")
FAISS_META_PATH = os.getenv("FAISS_META_PATH", "/data/faiss/meta.json")

PROJECT_CLONE_PATH = os.getenv("PROJECT_CLONE_PATH", "/data/project_clone")
UPLOADS_PATH = os.getenv("UPLOADS_PATH", "/data/uploads")
PROMPTS_LOG = os.getenv("PROMPTS_LOG", "/data/prompts_history/log.txt")

MAX_OUTPUT_TOKENS = int(os.getenv("MAX_OUTPUT_TOKENS", 1500))
TEMPERATURE = float(os.getenv("TEMPERATURE", 0.2))
