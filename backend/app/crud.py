from sqlalchemy.orm import Session
from . import models
from typing import List

def create_repo(db: Session, name: str, url: str):
    repo = models.Repo(name=name, url=url)
    db.add(repo)
    db.commit()
    db.refresh(repo)
    return repo

def get_repo(db: Session, repo_id: int):
    return db.query(models.Repo).filter(models.Repo.id == repo_id).first()

def create_scan(db: Session, repo_id: int):
    scan = models.Scan(repo_id=repo_id)
    db.add(scan)
    db.commit()
    db.refresh(scan)
    return scan

def create_issue(db: Session, scan_id: int, rule_id: str, severity: str, category: str, **kwargs):
    issue = models.Issue(scan_id=scan_id, rule_id=rule_id, severity=severity, category=category, **kwargs)
    db.add(issue)
    db.commit()
    db.refresh(issue)
    return issue

def get_issues_by_repo(db: Session, repo_id: int, status: str = None) -> List:
    query = db.query(models.Issue).join(models.Scan).filter(models.Scan.repo_id == repo_id)
    if status:
        query = query.filter(models.Issue.status == status)
    return query.all()

def update_issue_status(db: Session, issue_id: int, status: str):
    issue = db.query(models.Issue).filter(models.Issue.id == issue_id).first()
    if issue:
        issue.status = status
        db.commit()
    return issue