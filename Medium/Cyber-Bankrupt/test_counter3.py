#!/usr/bin/env python3
"""Test if ops counter reset works with longer timeout."""
from pwn import *
import time

context.log_level = 'info'
BINDIR = '/home/gluppler/Downloads/CTFs-Testing/Pwn/Medium/Cyber-Bankrupt/challenge'

p = process(['./glibc/ld-linux-x86-64.so.2', '--library-path', './glibc/', './cyber_bankrupt'], cwd=BINDIR)
p.recvuntil(b'pin:')
p.sendline(b'6969')

# Op1: normal alloc
log.info('Op1: alloc')
p.sendlineafter(b'> ', b'1')
p.sendlineafter(b'Bank ID: ', b'0')
p.sendlineafter(b'transfer: ', b'497')
p.sendafter(b'receiver: ', b'A')
p.recvuntil(b'succeed!', timeout=10)

# Op2: 128-byte alloc (may reset counter)
log.info('Op2: 128-byte alloc')
p.sendlineafter(b'> ', b'1')
p.sendlineafter(b'Bank ID: ', b'0')
p.sendlineafter(b'transfer: ', b'497')
p.sendafter(b'receiver: ', b'B' * 128)
try:
    p.recvuntil(b'succeed!', timeout=10)
    log.success('Op2 succeed!')
except:
    log.error('Op2 timeout on succeed!')
    # Check what's in buffer
    try:
        buf = p.recv(4096, timeout=1)
        log.info(f'Buffer: ...{buf[-200:]}')
    except:
        pass
    p.close()
    exit()

# Op3: try another operation
log.info('Op3: try another alloc')
try:
    p.sendlineafter(b'> ', b'1', timeout=5)
    p.sendlineafter(b'Bank ID: ', b'0', timeout=5)
    p.sendlineafter(b'transfer: ', b'32', timeout=5)
    p.sendafter(b'receiver: ', b'C')
    p.recvuntil(b'succeed!', timeout=10)
    log.success('Op3 succeed! Counter was likely reset!')
except Exception as e:
    log.error(f'Op3 failed: {e}')
    # Check buffer
    try:
        buf = p.recv(4096, timeout=1)
        log.info(f'Buffer: ...{buf[-300:]}')
    except:
        pass

# Op4-Op14: try many more ops  
for i in range(4, 15):
    try:
        p.sendlineafter(b'> ', b'2', timeout=3)
        p.sendlineafter(b'Bank ID: ', b'0', timeout=3)
        p.recvuntil(b'out!', timeout=5)
        
        p.sendlineafter(b'> ', b'1', timeout=3)
        p.sendlineafter(b'Bank ID: ', b'0', timeout=3)
        p.sendlineafter(b'transfer: ', b'32', timeout=3)
        p.sendafter(b'receiver: ', b'D')
        p.recvuntil(b'succeed!', timeout=5)
        log.info(f'Op{i}: OK')
    except Exception as e:
        log.info(f'Op{i}: {e}')
        break

# Final check
log.info(f'Alive: {p.poll() is None}')
if p.poll() is None:
    log.success('Infinite operations confirmed!')
p.close()
