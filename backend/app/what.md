Repo: {id, name, url, last_scan_date}.
Scan: {id, repo_id, timestamp, raw_results (list of issues)}.
Issue: {id, scan_id, severity (low/med/high/crit), type (secret/dep/code), desc, file_path, status (open/fixed/ignored), ai_suggestion}.
Flow: Add Repo → Trigger Scan (manual or scheduled) → Run Scanners (parallel if possible) → Enrich with AI → Store/Triage Issues → Query for Reports (e.g., vulns by severity).