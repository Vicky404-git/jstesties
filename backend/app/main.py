from fastapi import FastAPI, Depends, HTTPException
from sqlalchemy.orm import Session
import asyncio
from . import models, crud, scanners
from .models import get_db

app = FastAPI(title="Scanforge Backend")

@app.post("/repos/")
def add_repo(name: str, url: str, db: Session = Depends(get_db)):
    return crud.create_repo(db, name, url)

@app.get("/repos/{repo_id}")
def view_repo(repo_id: int, db: Session = Depends(get_db)):
    repo = crud.get_repo(db, repo_id)
    if not repo:
        raise HTTPException(404, "Repo not found")
    return repo

@app.post("/scans/{repo_id}")
async def trigger_scan(repo_id: int, db: Session = Depends(get_db)):
    repo = crud.get_repo(db, repo_id)
    if not repo:
        raise HTTPException(404, "Repo not found")
    issues = await scanners.full_scan(repo.url)
    scan = crud.create_scan(db, repo_id)
    for issue_dict in issues:
        # Map dict to DB fields
        crud.create_issue(db, scan.id, issue_dict['rule_id'], issue_dict['severity'], issue_dict['category'],
                          description=issue_dict['description'], file_path=issue_dict['file_path'],
                          line_number=issue_dict['line_number'], snippet=issue_dict['snippet'])
    return {"scan_id": scan.id, "issues": len(issues)}

@app.get("/issues/{repo_id}")
def get_issues(repo_id: int, status: str = None, db: Session = Depends(get_db)):
    return crud.get_issues_by_repo(db, repo_id, status)

@app.patch("/issues/{issue_id}/status")
def update_status(issue_id: int, status: str, db: Session = Depends(get_db)):
    issue = crud.update_issue_status(db, issue_id, status)
    if not issue:
        raise HTTPException(404, "Issue not found")
    return issue

# Add /scans/{repo_id}/history for UI charts (aggregate severities)