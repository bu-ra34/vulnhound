import os
import sys
import tarfile

path = sys.argv[1]
os.system("cat " + path)  # VH-EXPECT: cmdi

user_code = input("code> ")
exec(user_code)  # VH-EXPECT: code-exec

with tarfile.open(sys.argv[2]) as tf:  # VH-EXPECT: path-traversal
    tf.extractall(sys.argv[3])  # VH-EXPECT: path-traversal
