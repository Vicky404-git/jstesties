import asyncio
import sys
from scanner import full_scan  # Adjust if file is named 'scanner.py'

print("Step 1: Starting test scan...")  # Debug: Always prints

async def test():
    print("Step 2: Inside async test()...")  # Debug
    repo_url = 'https://github.com/Vicky404-git/jstesties.git'  # Simple public repo
    print(f"Step 3: Using repo URL: {repo_url}")  # Debug
    
    try:
        print("Step 4: Calling full_scan...")  # Debug
        issues = await full_scan(repo_url)
        print(f"Step 5: Scan complete! Found {len(issues)} issues.")  # Debug
        
        if issues:
            print("First 3 issues:")
            for i in issues[:3]:
                print(f"  - Rule {i['rule_id']} ({i['severity']}): {i['description'][:50]}...")
        else:
            print("No issues found (normal for a clean repo like Hello-World).")
    except Exception as e:
        print(f"Error during scan: {e}", file=sys.stderr)  # Catch & print errors
        import traceback
        traceback.print_exc()  # Full stack trace

if __name__ == "__main__":
    print("Step 0: Script launched.")  # Debug
    asyncio.run(test())
    print("Step 6: Test finished.")  # Debug