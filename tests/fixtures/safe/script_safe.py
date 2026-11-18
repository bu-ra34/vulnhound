import ast
import os
import subprocess
import sys

count = int(sys.argv[1])
os.system("echo " + str(count))
subprocess.run(["ls", "-l"], check=True)
value = ast.literal_eval("{'a': 1}")
home = os.environ.get("HOME", "/root")
print(count, value, home)
