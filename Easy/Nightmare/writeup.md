---
title: "Nightmare"
ctf: "Hack The Box"
date: 2026-06-13
category: pwn
difficulty: easy
flag_format: "HTB{...}"
author: "gluppler"
---

# Nightmare

## Summary

Format string vulnerability in a 64-bit PIE binary with No RELRO, canary, and NX enabled. Remote stderr is not forwarded, so leaking via `fprintf(stderr, ...)` (option 1) is invisible. Instead, leak via `printf(...)` (option 2, 6-byte limited input) using three rounds of `%N$p` format specifiers. Write via option 1's `fprintf(stderr, buf)` — the GOT overwrite still executes even though output is invisible. Overwrite `printf@GOT` with `system`, then trigger a shell via option 2 with `sh`.

## Solution

### Reconnaissance

The binary has two format string vulnerabilities:
- **Option 1** (`Scream`): `fgets(buf, 256, stdin)` → `fprintf(stderr, buf)` — output to stderr
- **Option 2** (`Escape`): `fgets(buf, 6, stdin)` → `strncmp(buf, "buster", 5)` → `printf(buf)` — output to stdout

Remote stderr is not forwarded over the network (confirmed via nc). Therefore:
- Leak via option 2 (one `%N$p` at a time, max 5 bytes per format)
- Write via option 1 (GOT overwrite works even though fprintf output is invisible)

### Gotcha: 5-byte format strings leave `\n` in stdin

`fgets(buf, 6, stdin)` reads at most 5 characters. For a 4-char format like `%7$p`, fgets reads all 5 bytes (4 chars + `\n`). For a 5-char format like `%13$p`, fgets reads only the 5 characters and leaves `\n` in stdin. This leftover newline is consumed by `main()`'s first `getchar()` as an invalid menu option (triggering `"No can do"`), but the SECOND `getchar()` blocks forever. Must send a dummy byte to unblock it before continuing.

### Stack Leaks (option 2)

| Offset | Format | What |
|--------|--------|------|
| `%7$p` | 4 chars | Stack canary |
| `%9$p` | 4 chars | PIE return address (PIE + 0x14d5) |
| `%13$p` | 5 chars | `__libc_start_main` return (glibc 2.31 → libc + 0x270b3) |

Libc identified as glibc 2.31 (Ubuntu 20.04): `__libc_start_main + 0x270b3`, `system` at offset 0x55410.

### GOT Overwrite (option 1)

Use `fmtstr_payload(5, {printf_got: system_addr}, write_size='byte')` to overwrite `printf@GOT` with `system`. The format string buffer starts at argument position 5 for `fprintf(stderr, buf)` (because `stderr` is arg 1, `buf` is arg 2 as the format string, and the buffer contents on the stack start at variadic argument 5).

### Trigger

Select option 2, send `sh`. After the overwrite:
1. `printf("Enter the escape code>> ")` → `system("Enter the escape code>> ")` — harmless bash error to stderr
2. `fgets(buf, 6, stdin)` reads our `"sh"`
3. `printf(buf)` → `system("sh")` → shell

### Flag

```
HTB{ar3_y0u_w0k3_y3t!?}
```
