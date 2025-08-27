from fastapi import FastAPI, UploadFile, File, Form, HTTPException
from fastapi.responses import JSONResponse
from utils import save_upload_file, log_prompt
from worker import process_pdf
from db_models import init_db
from config import PROJECT_CLONE_PATH, PROMPTS_LOG
from embeddings_utils import encode_texts
import requests, os, json, shutil, subprocess
from gemini_client import ask_gemini
from github_integration import git_clone_repo, create_branch_and_push, create_pr_via_api
# Em app/app.py
from pydantic import BaseModel

# --- Modelos Pydantic ---
class FrontendChangeRequest(BaseModel):
    prompt: str
    target_file: str 

# --- Inicialização da Aplicação ---
app = FastAPI(title="AI Assistant API")

init_db()


# --- Endpoint para Modificação do Frontend ---
@app.post("/frontend/modify")
def modify_frontend(request: FrontendChangeRequest):
    """
    Recebe um prompt para modificar um arquivo do frontend, clona o repositório,
    aplica a modificação e envia um push para o GitHub, acionando um deploy na Vercel.
    """
    # --- 1. Configuração e Limpeza ---
    # Garanta que a variável FRONTEND_REPO_NAME exista no seu .env
    # Ex: FRONTEND_REPO_NAME=seu-usuario/seu-repo-de-frontend
    frontend_repo_name = os.getenv("FRONTEND_REPO_NAME")
    github_token = os.getenv("GITHUB_TOKEN")

    if not frontend_repo_name or not github_token:
        raise HTTPException(status_code=500, detail="As variáveis de ambiente FRONTEND_REPO_NAME e GITHUB_TOKEN devem ser configuradas.")

    repo_url = f"https://{github_token}@github.com/{frontend_repo_name}.git"
    clone_dir = "/tmp/frontend_repo_clone"

    # Limpa o diretório de clone, se ele já existir, para garantir uma cópia limpa
    if os.path.exists(clone_dir):
        shutil.rmtree(clone_dir)

    # --- 2. Clonar o Repositório do Frontend ---
    try:
        print(f"Clonando {frontend_repo_name}...")
        subprocess.run(
            ["git", "clone", repo_url, clone_dir], 
            check=True, capture_output=True, text=True
        )
        print("Clone bem-sucedido.")
    except subprocess.CalledProcessError as e:
        print(f"Erro no clone: {e.stderr}")
        raise HTTPException(status_code=500, detail=f"Falha ao clonar o repositório: {e.stderr}")

    # --- 3. Modificar o Arquivo ---
    file_to_modify = os.path.join(clone_dir, request.target_file)
    
    if not os.path.exists(file_to_modify):
        raise HTTPException(status_code=404, detail=f"Arquivo não encontrado no repositório: {request.target_file}")

    try:
        print(f"Modificando o arquivo: {file_to_modify}...")
        with open(file_to_modify, 'r', encoding='utf-8') as f:
            content = f.read()

        # =============================================================================
        # LÓGICA DE MODIFICAÇÃO (PRIMEIRO TESTE)
        # ADAPTE AS DUAS LINHAS ABAIXO PARA ALGO QUE EXISTA NO SEU ARQUIVO DE LOGIN
        # =============================================================================
        texto_original = "Entrar"  # Ex: O texto dentro de um <h1> ou <title>
        texto_modificado = "Login Modificado pelo Assistente AI"
        
        if texto_original not in content:
            raise HTTPException(status_code=400, detail=f"O texto de teste '{texto_original}' não foi encontrado no arquivo. Adapte a função em app.py.")
            
        content = content.replace(texto_original, texto_modificado)
        # =============================================================================

        with open(file_to_modify, 'w', encoding='utf-8') as f:
            f.write(content)
        print("Arquivo modificado com sucesso.")

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Falha ao ler ou escrever no arquivo: {e}")

    # --- 4. Comitar e Enviar a Alteração (Push) ---
    try:
        print("Enviando alterações para o GitHub...")
        git_cmd = ["git", "-C", clone_dir] # Executa comandos git dentro do diretório clonado
        
        subprocess.run(git_cmd + ["config", "user.name", "AI Assistant Bot"], check=True)
        subprocess.run(git_cmd + ["config", "user.email", "bot@example.com"], check=True)
        
        subprocess.run(git_cmd + ["add", "."], check=True)
        commit_message = f"feat: Modifica '{request.target_file}' via AI Assistant"
        subprocess.run(git_cmd + ["commit", "-m", commit_message], check=True)
        subprocess.run(git_cmd + ["push"], check=True)
        print("Push para o GitHub bem-sucedido.")
    except subprocess.CalledProcessError as e:
        print(f"Erro no git push: {e.stderr}")
        raise HTTPException(status_code=500, detail=f"Falha ao fazer o push para o repositório: {e.stderr}")

    # --- 5. Limpeza Final ---
    shutil.rmtree(clone_dir)

    return {"message": f"Modificação no arquivo '{request.target_file}' enviada com sucesso! A Vercel iniciará o deploy."}


# --- Endpoints Administrativos Existentes ---
@app.post("/admin/upload")
async def admin_upload(theme: str = Form(...), file: UploadFile = File(...)):
    # ... (seu código existente)
    content = await file.read()
    path = save_upload_file(content, filename=file.filename)
    task = process_pdf.delay(path, theme)
    return {"status": "processing", "task_id": task.id, "file": path}

@app.post("/admin/process-repo")
def admin_process_repo(issue_description: str = Form(...), create_pr: bool = Form(False)):
    # ... (seu código existente)
    repo_dir = git_clone_repo()
    code_texts = []
    filepaths = []
    # ... (resto do seu código existente)
    return {"status": "branch_pushed", "branch": "branch_name_aqui"}