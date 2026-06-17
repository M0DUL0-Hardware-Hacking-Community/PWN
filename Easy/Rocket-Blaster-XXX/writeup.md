# Rocket-Blaster-XXX — Pwn/Easy

**Flag**: `HTB{b00m_b00m_b00m_3_r0ck3t5_t0_th3_m00n}`

## Analysis

- **Binary**: x86-64 ELF, dynamically linked, not stripped
- **Protections**: Full RELRO, no canary, NX enabled, no PIE
- **Bundled libc**: `./glibc/` with interpreter `./glibc/ld-linux-x86-64.so.2`

The `main()` function:
1. Calls `banner()` (prints ASCII art)
2. `read(0, rbp-0x20, 0x66)` — reads 102 bytes into a 32-byte buffer → buffer overflow
3. Calls `puts("Preparing beta testing..")` and returns

The win function `fill_ammo(rdi, rsi, rdx)` at `0x4012f5`:
- Opens `./flag.txt`
- Checks `rdi == 0xdeadbeef`, `rsi == 0xdeadbabe`, `rdx == 0xdead1337`
- If all pass, prints the flag content

## Exploit

**Ret2win with 3 arguments.** Since this is a no-PIE x86-64 binary, we use ROP with three `pop; ret` gadgets to set the registers:

| Gadget | Address |
|--------|---------|
| `pop rdi; ret` | `0x40159f` |
| `pop rsi; ret` | `0x40159d` |
| `pop rdx; ret` | `0x40159b` |
| `ret` (alignment) | `0x40101a` |
| `fill_ammo` | `0x4012f5` |

**Stack alignment**: Without the `ret` gadget before `fill_ammo`, the `call printf` inside `fill_ammo` crashes on `movaps` (RSP misaligned by 8). The `ret` gadget fixes this.

**Payload (104 bytes)**:
```
40 bytes padding (buffer + saved rbp)
8 bytes pop_rdi
8 bytes 0xdeadbeef
8 bytes pop_rsi
8 bytes 0xdeadbabe
8 bytes pop_rdx
8 bytes 0xdead1337
8 bytes ret (alignment)
8 bytes fill_ammo
```

**Note**: `read()` is limited to `0x66 = 102` bytes, but the payload is 104. The last 2 bytes of `fill_ammo`'s address `0x4012f5` are `0x0000`, which happen to match the original stack zeros at those positions — so the truncated write still produces the correct address.

## Tools
- pwntools
- ROPgadget (for gadget discovery)
