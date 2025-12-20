AWS_KEY = "AKIAEXAMPLE123456789"  # Rule 1.1
admin_pass = "password123!"     # Rule 1.6
user_input = input()

result = eval("calculate(" + user_input + ")")  # Rule 2.1

# Fake / test API keys for scanner validation
# THESE ARE NOT REAL KEYS

AWS_ACCESS_KEY_ID = "AKIA1234567890ABCDE"
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

GOOGLE_API_KEY = "AIzaSyA-1234567890abcdefGhijkLMNOP"

STRIPE_SECRET_KEY = "sk_test_51H8eFakeKey1234567890"

GENERIC_API_KEY = "api_key = 1234567890abcdefTOKEN"

GITHUB_TOKEN = "ghp_1234567890abcdef1234567890abcdef"

DATABASE_PASSWORD = "password=supersecretpassword123"

def connect():
    print("This file is only for testing secret detection")

