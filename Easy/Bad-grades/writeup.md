# Bad-grades - Pwn (Easy)

**Binary:** 64-bit ELF, Full RELRO, Canary, NX, No PIE, stripped  
**Vulnerability:** Unchecked loop count in `add_grades` → stack buffer overflow

---

## Analysis

The binary manages grades with two options:
1. **View** — prints hardcoded grades and exits
2. **Add** — reads a number of grades, then loops reading doubles with `scanf("%lf")`

The `add_grades` function allocates a 0x120-byte stack frame with a grades buffer at `rbp-0x110`. There is **no upper bound check** on the grade count — the loop condition is simply `i < num_grades` where `num_grades` is user-controlled.

**Stack layout (grade indices):**
| Index | Offset | Content |
|-------|--------|---------|
| 0–32  | rbp-0x110 … rbp-0x10 | Grades buffer |
| **33** | **rbp-0x8** | **Stack canary** |
| 34    | rbp+0x0 | Saved RBP |
| 35    | rbp+0x8 | Return address |

## Exploit — scanf Format-Error Skip

The canary is preserved using a **scanf format-error skip**: feeding `-` to `scanf("%lf")` causes a match failure (`-` is a valid prefix for a negative float but incomplete). The `-` is consumed but nothing is written to the destination, so the canary stays intact. Subsequent `scanf` calls work normally.

**Two-stage ROP:**
1. **Leak:** overwrite saved RBP and return address with `pop rdi; ret` → `puts@got` → `puts@plt` → `main` to leak libc and restart
2. **Shell:** same overflow with `ret` (alignment) → `pop rdi; ret` → `/bin/sh` → `system`

## Gadgets (No PIE, fixed at 0x400000)
- `pop rdi; ret` → `0x401263`
- `ret` (alignment) → `0x400666`
- `puts@plt` → `0x400680`
- `puts@got` → `0x601fa8`
- `main` → `0x401108`

## Flag
`HTB{c4n4ry_1s_4fr41d_0f_s1gn3d_numb3r5}`
