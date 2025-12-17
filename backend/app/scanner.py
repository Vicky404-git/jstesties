import os, re, math, json
import subprocess, tempfile, asyncio
from pathlib import Path
from typing import List, Dict
from git import Repo
#from detect_secrets import SecretsCollection
from bandit.core import manager as BanditManager
import yaml  # For YAML parsing
import safety  # For Python deps

# Issue format: {'rule_id': '1.1', 'severity': 'Critical', 'description': str, 'file_path': str, 'line_number': int, 'snippet': str, 'category': str}

# PDF Descriptions (hardcoded; extend as needed)
RULE_DESCS = {
    '1.1': 'Detects hardcoded AWS Access Key IDs. Leaking these allows an attacker to gain access to your AWS account, potentially leading to data theft, resource hijacking, and significant financial loss.',
    '1.2': 'Scans for private key blocks (e.g., RSA, OPENSSH, PGP). If leaked, an attacker can impersonate services or users and decrypt sensitive data.',
    '1.3': 'Finds complete database connection strings, which often contain the database type, host, port, username, and password in plain text, giving an attacker direct access to your database.',
    '1.4': 'Looks for strings with a high degree of randomness (high entropy), which are likely generic API keys (e.g., Stripe, SendGrid, etc.). These keys are often assigned to variables with names like API_KEY or SECRET.',
    '1.5': 'Detects hardcoded Slack Webhook URLs. These URLs allow anyone to post messages into a specific Slack channel, which can be used for spam, phishing, or leaking internal information.',
    '1.6': 'Scans for variables with suspicious names (e.g., password, pass, secret, pwd) assigned a static string value.',
    '1.7': 'Finds hardcoded JSON Web Tokens (JWTs). If a long-lived JWT is hardcoded (e.g., for testing), an attacker can copy it and use it to impersonate a user.',
    '2.1': 'The eval() function executes a string as code. If any part of the string comes from user input, an attacker can inject malicious code, leading to an RCE vulnerability.',
    '2.2': 'Deserializing (unpickling) data from an untrusted source can execute arbitrary code, as the pickle file can be crafted to run commands upon being loaded.',
    '2.3': 'Detects the use of weak hashing algorithms like MD5 and SHA1, especially for hashing passwords. These algorithms are "broken," allowing an attacker to recover the original password using "rainbow tables."',
    '2.4': 'Looks for code that disables SSL/TLS certificate validation when making HTTPS requests. This allows an attacker to perform a Man-in-the-Middle (MITM) attack by presenting a fake certificate and intercepting all traffic.',
    '2.5': 'Detects SQL queries built by directly formatting user input into the query string. This is the classic entry point for an SQL Injection (SQLi) attack.',
    '2.6': 'Flags the use of mktemp() (or tempfile.mktemp() in Python). This creates a "race condition" where an attacker could create a file (e.g., a symlink) with that name first to trick the program into overwriting other files.',
    '3.1': 'By default, containers run as the root user. If an attacker compromises the application, they gain root privileges inside the container, making it easier to escalate their attack.',
    '3.2': 'The setting privileged: true in a Kubernetes Pod specification gives the container full, unrestricted access to the host machine (the node), effectively disabling all container isolation.',
    '3.3': 'Exposing port 22 (EXPOSE 22) in a Dockerfile implies an SSH server is running inside the container, which is an anti-pattern that increases the attack surface.',
    '3.4': 'A container without CPU or memory limits can consume all the resources on its host node, leading to a Denial of Service (DoS) and node instability.',
    '4.1': "Parses your requirements.txt file and checks each package and its version against a database of known vulnerabilities. Using a library with a known RCE or SQLi vulnerability is a direct, exploitable risk.",
    '4.2': "Parses your package.json file and checks dependencies and devDependencies against a database of known vulnerabilities. The npm ecosystem moves fast, and old packages often have critical vulnerabilities.",
    '4.3': "Parses a Java project's pom.xml (Maven) file and checks its dependencies. This is critical for finding issues like Log4Shell, one of the most severe vulnerabilities in recent history."
}

SEVERITIES = {
    '1.1': 'Critical', '1.2': 'Critical', '1.5': 'Critical',
    '1.3': 'High', '1.4': 'High', '1.6': 'High', '1.7': 'High',
    '2.1': 'High', '2.2': 'High', '2.4': 'High', '2.5': 'High',
    '2.3': 'Medium', '2.6': 'Medium',
    '3.1': 'Medium', '3.3': 'Medium', '3.4': 'Medium',
    '3.2': 'Critical',
    '4.1': 'High', '4.2': 'High', '4.3': 'High'
}

CATEGORIES = {
    '1.1': '1', '1.2': '1', '1.3': '1', '1.4': '1', '1.5': '1', '1.6': '1', '1.7': '1',
    '2.1': '2', '2.2': '2', '2.3': '2', '2.4': '2', '2.5': '2', '2.6': '2',
    '3.1': '3', '3.2': '3', '3.3': '3', '3.4': '3',
    '4.1': '4', '4.2': '4', '4.3': '4'
}

def clone_repo(repo_url: str, temp_dir: str) -> Path:
    """Clone repo to temp dir."""
    repo = Repo.clone_from(repo_url, temp_dir)
    return Path(temp_dir)

def calculate_entropy(s: str) -> float:
    """Shannon entropy for high-entropy detection (rule 1.4)."""
    if not s:
        return 0.0
    entropy = 0
    for x in range(256):
        p_x = float(s.count(chr(x))) / len(s)
        if p_x > 0:
            entropy += - p_x * math.log2(p_x)
    return entropy / math.log2(256) * 8  # Normalize to bits/char

async def scan_category_1_secrets(temp_dir: Path) -> List[Dict]:
    """Category 1: Hardcoded Secrets (pure regex—no detect-secrets needed)."""
    issues = []
    
    # Walk all files (focus on code/configs)
    for root, _, files in os.walk(temp_dir):
        for file in files:
            file_path = os.path.join(root, file)
            if file.endswith(('.py', '.js', '.ts', '.json', '.env', '.yaml', '.yml')):  # Target likely spots
                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        for line_num, line in enumerate(f.readlines(), 1):
                            snippet = line.strip()
                            
                            # 1.1 AWS Key
                            if re.search(r'AKIA[0-9A-Z]{16}', snippet):
                                issues.append({
                                    'rule_id': '1.1', 'severity': 'Critical',
                                    'description': RULE_DESCS['1.1'], 'file_path': file_path,
                                    'line_number': line_num, 'snippet': snippet,
                                    'category': '1'
                                })
                            
                            # 1.2 Private Key (headers/footers)
                            elif re.search(r'-----BEGIN [A-Z ]+PRIVATE KEY-----|-----END [A-Z ]+PRIVATE KEY-----', snippet, re.I):
                                issues.append({
                                    'rule_id': '1.2', 'severity': 'Critical',
                                    'description': RULE_DESCS['1.2'], 'file_path': file_path,
                                    'line_number': line_num, 'snippet': snippet,
                                    'category': '1'
                                })
                            
                            # 1.3 DB Conn String
                            elif re.search(r'(postgres|mysql|oracle|sqlite)://[^@]+@[^:]+:\d+/', snippet, re.I):
                                issues.append({
                                    'rule_id': '1.3', 'severity': 'High',
                                    'description': RULE_DESCS['1.3'], 'file_path': file_path,
                                    'line_number': line_num, 'snippet': snippet,
                                    'category': '1'
                                })
                            
                            # 1.5 Slack Webhook
                            elif re.search(r'https://hooks\.slack\.com/services/[A-Z0-9_]{8,}/[A-Z0-9_]{8,}/[A-Z0-9_]{24}', snippet):
                                issues.append({
                                    'rule_id': '1.5', 'severity': 'Critical',
                                    'description': RULE_DESCS['1.5'], 'file_path': file_path,
                                    'line_number': line_num, 'snippet': snippet,
                                    'category': '1'
                                })
                            
                            # 1.6 Hardcoded Passwords (var names + static strings)
                            elif re.search(r'(password|pass|secret|pwd|key)\s*[:=]\s*["\']([^"\']{3,})["\']', snippet, re.I):
                                issues.append({
                                    'rule_id': '1.6', 'severity': 'High',
                                    'description': RULE_DESCS['1.6'], 'file_path': file_path,
                                    'line_number': line_num, 'snippet': snippet,
                                    'category': '1'
                                })
                            
                            # 1.7 JWT
                            elif re.search(r'^ey[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_.+/]*=?$', snippet):
                                issues.append({
                                    'rule_id': '1.7', 'severity': 'High',
                                    'description': RULE_DESCS['1.7'], 'file_path': file_path,
                                    'line_number': line_num, 'snippet': snippet,
                                    'category': '1'
                                })
                            
                            # 1.4 High-Entropy API Key (custom: long random strings near keywords)
                            keywords = ['API_KEY', 'SECRET', 'KEY', 'TOKEN']
                            strings = re.findall(r'["\']([A-Za-z0-9+/=]{20,})["\']', snippet)
                            for s in strings:
                                if any(kw in snippet.upper() for kw in keywords) and calculate_entropy(s) > 3.5:
                                    issues.append({
                                        'rule_id': '1.4', 'severity': 'High',
                                        'description': RULE_DESCS['1.4'], 'file_path': file_path,
                                        'line_number': line_num, 'snippet': snippet,
                                        'category': '1'
                                    })
                except Exception as e:
                    print(f"Skip file {file_path}: {e}")  # Graceful skip
    
    return issues

async def scan_category_2_code(temp_dir: Path) -> List[Dict]:
    """Category 2: Insecure Functions (using bandit + customs)."""
    issues = []
    
    # Find Python files
    py_files = list(temp_dir.rglob('*.py'))
    print(f"Debug: Found {len(py_files)} Python files for Bandit.")  # Debug: Skip if none
    
    if py_files:
        try:
            # Bandit scan (covers 2.1 eval B307, 2.2 pickle B301/B302, 2.3 weak hash B303/B304, 2.4 verify=False B501, 2.6 mktemp B108)
            mgr = BanditManager(config=None, agg_type='file', file_list=[str(f) for f in py_files])
            print("Debug: Running Bandit...")  # Debug
            mgr.run_tests()
            
            for issue in mgr.get_issue_list():
                file_path = issue.filename
                line_num = issue.lineno
                snippet = issue.code or f"Line {line_num} in {os.path.basename(file_path)}"  # Fallback
                test_id = issue.test_id
                
                rule_id = None
                if 'B307' in test_id:  # eval
                    rule_id = '2.1'
                elif 'B301' in test_id or 'B302' in test_id:  # pickle
                    rule_id = '2.2'
                elif 'B303' in test_id or 'B304' in test_id:  # md5/sha1
                    rule_id = '2.3'
                elif 'B501' in test_id:  # requests verify=False
                    rule_id = '2.4'
                elif 'B108' in test_id:  # mktemp
                    rule_id = '2.6'
                
                if rule_id:
                    issues.append({
                        'rule_id': rule_id, 'severity': SEVERITIES[rule_id],
                        'description': RULE_DESCS[rule_id], 'file_path': file_path,
                        'line_number': line_num, 'snippet': snippet,
                        'category': '2'
                    })
            print(f"Debug: Bandit found {len([i for i in issues if i['rule_id'].startswith('2')])} issues.")  # Debug
        except Exception as e:
            print(f"Bandit error (skipping): {e}")  # Graceful fallback
    
    # Custom for 2.5 SQL Injection (f-strings/concat; Bandit partial coverage)
    sql_pattern = r'(cursor|db)\.execute\s*\(\s*(f["\'][^"\']*\{[^}]*\}|[^"\']*\+user)'
    for py_file in py_files:
        try:
            with open(py_file, 'r') as f:
                for line_num, line in enumerate(f, 1):
                    if re.search(sql_pattern, line):
                        issues.append({
                            'rule_id': '2.5', 'severity': 'High',
                            'description': RULE_DESCS['2.5'], 'file_path': str(py_file),
                            'line_number': line_num, 'snippet': line.strip(),
                            'category': '2'
                        })
        except Exception:
            pass  # Skip bad files
    
    return issues

async def scan_category_3_configs(temp_dir: Path) -> List[Dict]:
    """Category 3: Misconfigs (custom parsing)."""
    issues = []
    
    # 3.1 Dockerfile root user
    dockerfiles = list(temp_dir.rglob('Dockerfile*'))
    for df in dockerfiles:
        with open(df, 'r') as f:
            lines = f.readlines()
            has_user = any(re.search(r'^USER\s+[^\sroot]', line, re.I) for line in lines)
            if not has_user or any(re.search(r'^USER\s+root', line, re.I) for line in lines):
                issues.append({
                    'rule_id': '3.1', 'severity': 'Medium',
                    'description': RULE_DESCS['3.1'], 'file_path': str(df),
                    'line_number': 0, 'snippet': 'Missing or root USER instruction',
                    'category': '3'
                })
    
    # 3.3 Expose SSH
    for df in dockerfiles:
        with open(df, 'r') as f:
            if re.search(r'^EXPOSE\s+22', f.read(), re.I):
                issues.append({
                    'rule_id': '3.3', 'severity': 'Medium',
                    'description': RULE_DESCS['3.3'], 'file_path': str(df),
                    'line_number': 0, 'snippet': 'EXPOSE 22 detected',
                    'category': '3'
                })
    
    # 3.2 & 3.4 Kubernetes YAML (privileged, missing limits)
    yamls = list(temp_dir.rglob('*.yaml')) + list(temp_dir.rglob('*.yml'))
    for yf in yamls:
        try:
            with open(yf, 'r') as f:
                data = yaml.safe_load(f)
            # Recursive check for containers
            def check_container(obj):
                if isinstance(obj, dict):
                    if 'securityContext' in obj and obj.get('privileged', False):
                        issues.append({
                            'rule_id': '3.2', 'severity': 'Critical',
                            'description': RULE_DESCS['3.2'], 'file_path': str(yf),
                            'line_number': 0, 'snippet': 'privileged: true',
                            'category': '3'
                        })
                    if 'resources' not in obj or 'limits' not in obj.get('resources', {}):
                        issues.append({
                            'rule_id': '3.4', 'severity': 'Medium',
                            'description': RULE_DESCS['3.4'], 'file_path': str(yf),
                            'line_number': 0, 'snippet': 'Missing resources.limits',
                            'category': '3'
                        })
                    for v in obj.values():
                        check_container(v)
            check_container(data)
        except yaml.YAMLError:
            pass  # Skip invalid YAML
    
    return issues

async def scan_category_4_deps(temp_dir: Path) -> List[Dict]:
    """Category 4: Vulnerable Dependencies."""
    issues = []
    
    # 4.1 Python (safety)
    req_files = list(temp_dir.rglob('requirements*.txt')) + list(temp_dir.rglob('Pipfile'))
    for req in req_files:
        try:
            vulns = safety.check(str(req))
            for vuln in vulns:
                issues.append({
                    'rule_id': '4.1', 'severity': 'High',
                    'description': RULE_DESCS['4.1'], 'file_path': str(req),
                    'line_number': 0, 'snippet': f"{vuln.package}=={vuln.version} (CVE: {vuln.vulnerability_id})",
                    'category': '4'
                })
        except Exception:
            pass
    
    # 4.2 Node.js (npm audit)
    if (temp_dir / 'package.json').exists():
        try:
            result = subprocess.run(['npm', 'audit', '--json'], cwd=temp_dir, capture_output=True, text=True)
            audit = json.loads(result.stdout)
            for dep in audit.get('metadata', {}).get('dependencies', {}):
                if 'via' in audit['metadata']['dependencies'][dep]:  # Vuln deps
                    issues.append({
                        'rule_id': '4.2', 'severity': 'High',
                        'description': RULE_DESCS['4.2'], 'file_path': str(temp_dir / 'package.json'),
                        'line_number': 0, 'snippet': f'"{dep}": vulnerable',
                        'category': '4'
                    })
        except (subprocess.CalledProcessError, json.JSONDecodeError):
            pass
    
    # 4.3 Java (simple regex for pom.xml; extend with OWASP dep-check CLI if needed)
    pom_files = list(temp_dir.rglob('pom.xml'))
    for pom in pom_files:
        with open(pom, 'r') as f:
            content = f.read()
            if re.search(r'<groupId>org\.apache\.logging\.log4j</groupId>.*?<version>2\.14\.0</version>', content, re.DOTALL):
                issues.append({
                    'rule_id': '4.3', 'severity': 'High',
                    'description': RULE_DESCS['4.3'], 'file_path': str(pom),
                    'line_number': 0, 'snippet': 'log4j-core 2.14.0 (Log4Shell)',
                    'category': '4'
                })
    
    return issues

async def full_scan(repo_url: str) -> List[Dict]:
    """Orchestrate all categories asynchronously."""
    with tempfile.TemporaryDirectory() as temp_dir_str:
        temp_dir = clone_repo(repo_url, temp_dir_str)
        
        # Run in parallel
        tasks = [
            scan_category_1_secrets(temp_dir),
            scan_category_2_code(temp_dir),
            scan_category_3_configs(temp_dir),
            scan_category_4_deps(temp_dir)
        ]
        results = await asyncio.gather(*tasks)
        
        all_issues = []
        for cat_issues in results:
            all_issues.extend(cat_issues)
        
        # Dedupe by file/line/rule
        seen = set()
        unique_issues = []
        for issue in all_issues:
            key = (issue['file_path'], issue['line_number'], issue['rule_id'])
            if key not in seen:
                seen.add(key)
                unique_issues.append(issue)
        
        # Sort by severity (Critical first)
        severity_order = {'Critical': 0, 'High': 1, 'Medium': 2}
        return sorted(unique_issues, key=lambda x: severity_order[x['severity']])