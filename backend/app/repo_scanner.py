from git import Repo
import os

Repo.clone_from(repo_url, "./repos/project1")

for root, dirs, files in os.walk("./repos/project1"):
    for file in files:
        if file.endswith((".js", ".py", ".ts")):
            print(os.path.join(root, file))
