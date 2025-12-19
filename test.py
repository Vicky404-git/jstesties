AWS_KEY = "AKIAEXAMPLE123456789"  # Rule 1.1
admin_pass = "password123!"     # Rule 1.6
user_input = input()
result = eval("calculate(" + user_input + ")")  # Rule 2.1

import os

# TEST DATA - DO NOT USE IN PRODUCTION
# These are fake keys designed to trigger secret scanners
# yoo


def get_config():
    return {
        # 1. Vendor Specific Patterns (Regex Matching)
        
        # AWS Access Key ID (Standard pattern: starts with AKIA, 20 chars)
        "aws_access_key_id": "AKIAIMNOJVMCUUE7FAKE", 
        
        # AWS Secret Key (High entropy, 40 chars)
        "aws_secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        
        # Stripe Live Key (Prefix: sk_live_)
        "stripe_key": "sk_ive_51Mz98234098234098234098234098234098234",
        
        # GitHub Personal Access Token (Prefix: ghp_)
        "github_token": "ghp_A1b2C3d4E5f6G7h8I9j0k1L2m3N4o5P6Q7R8",
        
        # Slack Bot Token (Prefix: xoxb-)
        "slack_token": "xoxb-123456789012-1234567890123-4mt0t4l1yF4k3T0k3n",

        # 2. Heuristic Matching (Variable Name + High Entropy)
        
        # Generic API Key
        "GOOGLE_MAPS_API_KEY": "AIzaSyD-FakeKeyForTestingPurposes123456",
        
        # Database Password (URI format)
        "DB_CONNECTION_STRING": "postgres://user:Sup3rS3cr3tP@ssw0rd!@localhost:5432/mydb"
    }