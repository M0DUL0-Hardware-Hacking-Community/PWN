#!/usr/bin/env python3
"""Debug counter reset: check what's in the output buffer after 128-byte alloc."""
from pwn import *
import time

context.log_level = 'error'
BINDIR = '/home/gluppler/Downloads/CTFs-Testing/Pwn/Medium/Cyber-Bankrupt/challenge'

p = process(['./glibc/ld-linux-x86-64.so.2', '--library-path', './glibc/', './cyber_bankrupt'], cwd=BINDIR)
p.recvuntil(b'pin:')
p.sendline(b'6969')

# 1st alloc (normal)
p.sendlineafter(b'> ', b'1')
p.sendlineafter(b'Bank ID: ', b'0')
p.sendlineafter(b'transfer: ', b'497')
p.sendafter(b'receiver: ', b'X')
p.recvuntil(b'succeed!', timeout=5)
print('Op1 OK', flush=True)

# 2nd alloc with 128 bytes
p.sendlineafter(b'> ', b'1')
p.sendlineafter(b'Bank ID: ', b'0')
p.sendlineafter(b'transfer: ', b'497')

# Instead of sendafter, manually send data
import socket
time.sleep(0.3)

# Now send the data (128 'Z' bytes)
data = b'Z' * 128
p.send(data)
time.sleep(0.5)

# Check what's in the output buffer before succeed
try:
    raw = p.recv(8192, timeout=2)
    print(f'Raw after 128-byte send ({len(raw)} bytes):', flush=True)
    # Show last 500 bytes
    print(repr(raw[-500:]), flush=True)
except:
    print('No data after 128-byte send', flush=True)

print(f'Alive: {p.poll() is None}', flush=True)

# Try sending newline to trigger read return
p.sendline(b'')
time.sleep(0.5)
try:
    raw2 = p.recv(8192, timeout=2)
    print(f'After newline ({len(raw2)} bytes):', flush=True)
    print(repr(raw2[-500:]), flush=True)
except:
    print('No data after newline', flush=True)

print(f'Alive: {p.poll() is None}', flush=True)
p.close()
