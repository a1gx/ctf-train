import os
import tempfile
import os
import string
import random
import sys

def randstr():
    return ''.join(random.choice(string.ascii_uppercase + string.digits + string.ascii_lowercase) for _ in range(10))

prefix = """
"""


size_max = 20000

code = prefix
new = ""
finished = False

while size_max > len(code):
    new = raw_input("code> ")
    if new == "EOF":
        finished = True
        break
    code += new + "\n"

if not finished:
    print("max length exceeded")
    sys.exit(42)

# save file
file_name = "/tmp/%s" % (randstr())
with open(file_name, "w+") as f:
    f.write(code.encode())

cmd = "/home/ctf/d8 ./%s" % file_name
os.system(cmd)

