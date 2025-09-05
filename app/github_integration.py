import os
import subprocess
import json
import tempfile
from config import GITHUB_TOKEN, GITHUB_HOST, REPO_NAME, PROJECT_CLONE_PATH

def git_clone_repo():
    # clone into PROJECT_CLONE_PATH (fresh for every run)
    repo_url = f"https://{GITHUB_TOKEN}@{GITHUB_HOST}/{REPO_NAME}.git"
    target = PROJECT_CLONE_PATH
    if os.path.exists(target):
        # remove existing to avoid conflicts
        subprocess.run(["rm", "-rf", target], check=True)
    subprocess.run(["git", "clone", repo_url, target], check=True)
    return target

def create_branch_and_push(repo_dir, branch):
    subprocess.run(["git", "checkout", "-b", branch], cwd=repo_dir, check=True)
    subprocess.run(["git", "add", "."], cwd=repo_dir, check=True)
    subprocess.run(["git", "commit", "-m", f"Automated fixes by AI assistant ({branch})"], cwd=repo_dir, check=True)
    # push
    remote = f"https://{GITHUB_TOKEN}@{GITHUB_HOST}/{REPO_NAME}.git"
    subprocess.run(["git", "push", remote, branch], cwd=repo_dir, check=True)

def create_pr_via_api(branch, title, body):
    # simpler: use GitHub REST to open PR
    import requests
    url = f"https://{GITHUB_HOST}/api/v3/repos/{REPO_NAME}/pulls" if GITHUB_HOST != "github.com" else f"https://api.github.com/repos/{REPO_NAME}/pulls"
    payload = {"title": title, "head": branch, "base": "main", "body": body}
    headers = {"Authorization": f"token {GITHUB_TOKEN}", "Accept": "application/vnd.github+json"}
    r = requests.post(url, json=payload, headers=headers)
    r.raise_for_status()
    return r.json().get("html_url")
