#!/usr/bin/python3

import sys
import os
import secrets
import string

# get filename to write to
filename = sys.argv[1]
if os.path.exists(filename):
    print(f"{filename} exists, aborting")
    sys.exit(0)

# create password
alphabet = string.ascii_letters + string.digits
password = "".join(secrets.choice(alphabet) for i in range(20))

# write password file
with open(filename, "w") as f:
    f.write(f"zapd:{{PLAIN}}{password}\n")
