#!/usr/bin/env python3
"""Definitive counter reset test. Each op takes ~10s due to loading bar."""
from pwn import *
import sys, time

context.log_level = 'info'
BINDIR = '/home/gluppler/Downloads/CTFs-Testing/Pwn/Medium/Cyber-Bankrupt/challenge'

p = process(['./glibc/ld-linux-x86-64.so.2', '--library-path', './glibc/', './cyber_bankrupt'], cwd=BINDIR)
p.recvuntil(b'pin:')
p.sendline(b'6969')

# Fast sequence: alloc + free + alloc with 128 bytes
def transfer(amount, data, timeout=30):
    p.sendlineafter(b'> ', b'1')
    p.sendlineafter(b'Bank ID: ', b'0')
    p.sendlineafter(b'transfer: ', str(amount).encode())
    p.sendafter(b'receiver: ', data)
    p.recvuntil(b'succeed!', timeout=timeout)

def free():
    p.sendlineafter(b'> ', b'2')
    p.sendlineafter(b'Bank ID: ', b'0')
    p.recvuntil(b'out!', timeout=30)

def view():
    p.sendlineafter(b'> ', b'3')
    p.sendlineafter(b'Bank ID: ', b'0')
    return p.recvline(timeout=30)

# Op1: alloc (counter: 0→1, but actually 1-based: first op has counter=0 from start)
# We need to know: what's the counter limit? Let's just test.
log.info('Doing ops until failure or 20 ops...')

op = 0
seen_succeed_since_reset = False
for i in range(25):
    try:
        if i == 2:  # 3rd operation: reset counter with 128 bytes
            log.info(f'--- Op {i+1}: Alloc with 128 bytes (reset) ---')
            transfer(0x1F1, b'R' * 128, timeout=30)
            log.success(f'Op {i+1}: OK')
        else:
            # Alloc+free or just alloc depending on even/odd
            if i % 2 == 0:
                transfer(0x60, b'X', timeout=30)
            else:
                free()
            if i > 2:
                seen_succeed_since_reset = True
        op += 1
    except Exception as e:
        log.info(f'Op {i+1}: FAILED: {e}')
        break
    # Check if alive
    if p.poll() is not None:
        log.error(f'Process died at op {i+1}!')
        break

log.info(f'Total ops completed: {op}')
log.info(f'Counter reset works: {seen_succeed_since_reset}')
p.close()
