---
title: "LiteServe"
ctf: "HTB Business CTF 2025"
date: 2026-06-11
category: pwn
difficulty: easy
points: N/A
flag_format: "HTB{...}"
---

# LiteServe

## Summary

Custom HTTP server with two chained vulnerabilities: a 4-byte buffer overflow in `get_mime_type()` that enables a debug flag, and a format string vulnerability in `parse_headers()` when debug is on and User-Agent starts with `"curl"`. The format string overwrites the `PRIV_MODE` global from `"OFF"` to `"ON"`, expanding the extension whitelist to include `.txt` and allowing access to `/flag.txt`.

## Solution

### Step 1: Overflow ctx->debug

The `get_mime_type()` function uses `memcpy(ctx->mime_type, ctx->file_extension, 0x24)` (36 bytes) but `mime_type` is only `0x20` (32 bytes). The 4-byte overflow reaches `ctx->debug` right after. Send a route whose extension starts with `"html"` (passes the extension check) but is 33+ bytes long (unknown to `get_mime_type`, so it takes the `memcpy` path):

```python
extension = b'A' * 0x21                 # 33 bytes
path = b'/file.' + extension            # extension = "html" + 29 A's
```

The overflow sets `ctx->debug` to a non-zero value, enabling debug messages.

### Step 2: Format string overwrite PRIV_MODE

With debug enabled, if `User-Agent` starts with `"curl"`, the code calls `printf(user_agent_value)` — a format string vulnerability.

The `PRIV_MODE` global is at `0x405169` (no PIE). Only 3 bytes of the address need to be embedded (upper bytes come from buffer zeroing). The format string uses a single `%n` write:

```python
priv_mode = 0x405169
head_idx = 8            # arg 8 = buffer + 4 (verified with %8$p)
fmt_len = 0x18          # format portion padded to 24 bytes
goal_val = u16(b'ON')   # 0x4e4f = 20047
fmt = f'%{goal_val-4}c%{head_idx + fmt_len//8}$n'.ljust(fmt_len, 'A').encode()
# = %20043c%11$n + 12 'A's (24 bytes total)
```

The address `\x69\x51\x40` (= first 3 bytes of `p64(0x405169)`) is placed right after the 24-byte format string. With `head_idx=8` and `fmt_len=24`, arg 11 points to `buffer + 4 + 24 = buffer + 28`, exactly where the 3-byte address sits. Combined with subsequent zero bytes in the buffer, the full 8-byte value read is `0x0000000000405169`.

The `%20043c` prints 20043 chars; with the 4-byte `"curl"` prefix, the total printed count is 20047 = `0x4e4f` = `"ON\x00\x00"` in little-endian. `%11$n` writes this 4-byte value to `PRIV_MODE`.

### Step 3: Request the flag

After `PRIV_MODE` is `"ON"`, send a second request:

```
GET /flag.txt HTTP/1.1
```

The `.txt` extension is now allowed, and the flag is returned.

## Flag

```
HTB{tH1s_w4s_L1gHt_w0rK}
```
