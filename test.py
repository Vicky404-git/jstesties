AWS_KEY = "AKIAEXAMPLE123456789"  # Rule 1.1
admin_pass = "password123!"     # Rule 1.6
user_input = input()
result = eval("calculate(" + user_input + ")")  # Rule 2.1


import os

# TEST DATA - GENERIC SECRETS
# GitHub usually ignores these because they don't match specific vendor regexes (like AWS/Stripe).
# However, your tool SHOULD catch them based on variable names (e.g. "SECRET") + random strings.

def get_database_config():
    return {
        # 1. Generic API Key (High Entropy String)
        # GitHub allows this because it doesn't know who "MY_SAAS" is.
        "MY_SAAS_API_KEY": "7f8a9d1c2b3e4f5g6h7i8j9k0l1m2n3o4p",

        # 2. Bearer Token (Common in Authorization headers)
        "AUTH_BEARER_TOKEN": "eyJhGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",

        # 3. Database Password (URI Format)
        # Scanners look for "postgres://" and "password" patterns
        "DB_CONNECTION_URI": "postgres://admin:Sup3rH@rdP@ssw0rd!@cluster0.example.com:5432/production",
        
        # 4. OAuth Client Secret (Random 32-byte hex)
        "OAUTH_CLIENT_SECRET": "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4y5z6",
        
        # 5. Private Key (Standard format but generated/fake content)
        # GitHub might flag the header, but often ignores if the content isn't valid RSA
        "SSH_PRIVATE_KEY": """-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACAC5yK9/12345FAKEKEYFORTESTINGPURPOSES12345...
-----END OPENSSH PRIVATE KEY-----"""
    }

def connect():
    # 6. Hardcoded Password in function call
    login("admin", "P@ssw0rd123!")