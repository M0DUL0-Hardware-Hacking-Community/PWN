#!/usr/bin/env python3
"""Probe remote interaction to see actual prompts."""
from pwn import *
import sys

context.log_level = 'debug'

host = sys.argv[1]
port = int(sys.argv[2])

r = remote(host, port, timeout=15)
data = r.recv(timeout=3)
print(f"BANNER: {data}")

r.sendline(b'pwn')
data = r.recv(timeout=3)
print(f"AFTER NAME: {data}")

# Option 2: create message
r.sendline(b'2')
data = r.recv(timeout=3)
print(f"AFTER OPTION 2: {data}")

# Send length
r.sendline(b'10')
data = r.recv(timeout=3)
print(f"AFTER LENGTH: {data}")

# Send content
r.sendline(b'AAAAAAAAAA')
data = r.recv(timeout=5)
print(f"AFTER CONTENT: {data}")

# Say n to continue
r.sendline(b'n')
data = r.recv(timeout=3)
print(f"AFTER N (continue): {data}")

# Say y to save
r.sendline(b'y')
data = r.recv(timeout=3)
print(f"AFTER Y (save): {data}")

r.close()
