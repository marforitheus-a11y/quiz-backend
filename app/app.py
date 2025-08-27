from fastapi import FastAPI, UploadFile, File, Form, HTTPException
from fastapi.responses import JSONResponse
from utils import save_upload_file, log_prompt
from worker import process_pdf
from db_models import init_db
from config import PROJECT_CLONE_PATH, PROMPTS_LOG
from embeddings_utils import encode_texts
import requests, os, json, shutil
from gemini_client import ask_gemini
from github_integration import git_clone_repo, create_branch_and_push, create_pr_via_api

app = FastAPI(title="AI Assistant API")

init_db()

@app.post("/admin/upload")
async def admin_upload(theme: str = Form(...), file: UploadFile = File(...)):
    content = await file.read()
    path = save_upload_file(content, filename=file.filename)
    # dispatch celery task
    task = process_pdf.delay(path, theme)
    return {"status": "processing", "task_id": task.id, "file": path}

@app.post("/admin/process-repo")
def admin_process_repo(issue_description: str = Form(...), create_pr: bool = Form(False)):
    """
    Ask the assistant to propose code fixes for 'issue_description'.
    It clones repo, retrieves relevant code chunks via FAISS (if any), calls Gemini to produce JSON mapping path->new content,
    writes files, creates branch, commits and pushes, then opens PR.
    """
    # 1) clone repo
    repo_dir = git_clone_repo()

    # 2) gather text content of repo files (limit size)
    code_texts = []
    filepaths = []
    for root, dirs, files in os.walk(repo_dir):
        for f in files:
            if f.endswith(('.py', '.js', '.ts', '.jsx', '.tsx', '.html', '.css', '.json')):
                fp = os.path.join(root, f)
                try:
                    with open(fp, "r", encoding="utf-8", errors="ignore") as fh:
                        txt = fh.read()
                    if len(txt) > 20000:
                        txt = txt[:20000]
                    code_texts.append(txt)
                    filepaths.append(os.path.relpath(fp, repo_dir))
                except Exception:
                    continue
    # encode and optionally call FAISS to retrieve relevant parts — here we'll just send top N files as context
    topN = 8
    context = ""
    for i, p in enumerate(filepaths[:topN]):
        context += f"=== FILE: {p} ===\n{code_texts[i]}\n\n"

    prompt = f"Description of desired change:\n{issue_description}\n\nRepository context (several files):\n{context}\n\nProduce a JSON object mapping file relative paths to their full new file contents (only include files that must change). Output must be strict JSON."
    answer = ask_gemini(prompt, "")
    log_prompt(prompt, answer)

    # parse JSON
    try:
        changes = json.loads(answer)
    except Exception:
        # try to extract JSON substring
        import re
        m = re.search(r'(\{.*\})', answer, re.S)
        if m:
            changes = json.loads(m.group(1))
        else:
            raise HTTPException(status_code=500, detail="Gemini did not return valid JSON with file mappings.")

    if not isinstance(changes, dict) or not changes:
        return {"status": "no_changes", "detail": "No changes returned by Gemini."}

    # write files into clone
    for rel_path, new_content in changes.items():
        full_path = os.path.join(repo_dir, rel_path)
        os.makedirs(os.path.dirname(full_path), exist_ok=True)
        with open(full_path, "w", encoding="utf-8") as f:
            f.write(new_content)

    branch_name = f"ai-fix-{abs(hash(issue_description))%100000}"
    if create_pr:
        create_branch_and_push(repo_dir, branch_name)
        pr_url = create_pr_via_api(branch_name, f"AI suggested fixes: {issue_description[:80]}", "Automated fixes suggested by AI assistant.")
        return {"status": "pr_created", "pr_url": pr_url}
    else:
        # commit to branch locally but do not push
        create_branch_and_push(repo_dir, branch_name)
        return {"status": "branch_pushed", "branch": branch_name}
