## Writeup — Execute (Pwn, Easy)

**Challenge**: `execute` binary reads 60 bytes into a stack buffer, checks for blacklisted bytes (0x3b, 0x54, 0x62, 0x69, 0x6e, 0x73, 0x68, 0xf6, 0xd2, 0xc0, 0x5f, 0xc9, 0x66, 0x6c, 0x61, 0x67), then calls the buffer as a function. NX is disabled (`-z execstack`).

**Blacklisted bytes** block: `execve` sysnum (0x3b), `b`, `i`, `n`, `s`, `h` (can't write `/bin/sh`), `f`, `l`, `a`, `g`, `_`, and a few instruction bytes (0xf6, 0xd2, 0xc0, 0xc9).

**Solution**: Write custom shellcode that avoids all blacklisted bytes:

1. **Zero rsi/rdx** via `push 0; pop rsi` / `push 0; pop rdx` (avoids `xor esi,esi` which contains 0xf6, and `xor edx,edx` which contains 0xd2)
2. **Push null terminator** with `push 0`
3. **Construct `//bin/sh`** using XOR technique — push a safe-looking value `0x657e2263646f2222`, then `xor [rsp]` with `0x0d0d0d0d0d0d0d0d` to yield `0x68732f6e69622f2f` ("//bin/sh")
4. **Set rdi** to `rsp` (pointer to the string)
5. **Set rax = 59** via `push 0x5b; pop rax; sub al, 0x20` (avoids the literal 0x3b byte)
6. **syscall**

**Remote IP**: `154.57.164.78:32706`
**Flag**: `HTB{f234212a6b5b1b387f8dd944446bd429}`
