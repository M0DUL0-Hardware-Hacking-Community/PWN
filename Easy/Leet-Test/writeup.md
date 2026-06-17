---
title: "Leet-Test"
ctf: "Hack The Box"
date: 2026-06-13
category: pwn
difficulty: easy
points: N/A
flag_format: "HTB{...}"
author: "gluppler"
---

# Leet-Test

## Summary

Format string vulnerability in a 64-bit ELF with No PIE and Partial RELRO. Two-round format string attack: leak a random value from the stack via `%7$p`, compute the required `winner` value (`rand * 0x1337c0de`), then write it to `winner` at `0x404078` using `%hhn` byte-writes to trigger the flag print.

## Solution

### Reconnaissance

The binary reads 4 bytes from `/dev/urandom`, masks to 16 bits, then loops:
1. `printf("Please enter your name: ")`
2. `fgets(buf, 0x100, stdin)` — 256 byte buffer at `rbp-0x120`
3. `printf("Hello, ")`
4. `printf(buf)` — **format string vulnerability**
5. Computes `random * 0x1337c0de` and compares with `winner` global at `0x404078`
6. If equal: opens `flag.txt`, reads it, prints `Come right in! %s`

Stack layout: random value at `rbp-0x134`, buf at `rbp-0x120`, canary at `rbp-0x8`.

### Format String Leak (Round 1)

`%7$p` reads the 7th format argument on the stack. At `printf(buf)` time, `%7$p` = `[rsp+8]`. The random value at `rbp-0x134` = `rsp+0xC` occupies the upper 32 bits of this qword. Extract via `(leak >> 32) & 0xFFFF`.

### Format String Write (Round 2)

The buffer starts at stack argument position 10 (`buf = rsp+0x20`, 6 register args + 4 qwords = position 10). `fmtstr_payload(10, {0x404078: target}, write_size='byte')` generates `%hhn` byte-writes to set `winner` to `target = (rand * 0x1337c0de) & 0xFFFFFFFF`.

### Flag

```
HTB{y0u_sur3_r_1337_en0ugh!!}
```
