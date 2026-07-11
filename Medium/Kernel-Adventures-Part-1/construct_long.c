#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

// Signed char version matching kernel's movsbl sign-extension
uint32_t hash_round(uint32_t r, uint8_t c) {
    int32_t sc = (int32_t)(int8_t)c;  // sign-extend
    r += sc;
    r *= 1025;
    r ^= (r >> 6);
    r ^= (uint32_t)sc;
    return r;
}

uint32_t inv_xor_shift_6(uint32_t y) {
    uint32_t x = y & 0xfc000000;
    for (int i = 25; i >= 0; i--) {
        uint32_t bit = ((y >> i) ^ (x >> (i + 6))) & 1;
        x |= (bit << i);
    }
    return x;
}

#define INV_1025 3222273025u

uint32_t inv_hash_round(uint32_t r_out, uint8_t c) {
    int32_t sc = (int32_t)(int8_t)c;
    uint32_t r_temp = r_out ^ (uint32_t)sc;
    uint32_t x = inv_xor_shift_6(r_temp);
    uint32_t r1 = x * INV_1025;
    return r1 - (uint32_t)sc;
}

#define TARGET 716661863u
#define PWDLEN 50

#define HT_SIZE (1 << 22)

struct entry { uint32_t hash; uint8_t a, b, c; struct entry *next; };

int main() {
    // Build forward table with signed semantics (only use bytes 1-127)
    int total_fwd = 127 * 127 * 127;
    struct entry **ht = calloc(HT_SIZE, sizeof(struct entry *));
    struct entry *pool = calloc(total_fwd, sizeof(struct entry));
    if (!ht || !pool) { perror("alloc"); return 1; }

    printf("Building 3-char forward table (bytes 1-127, %d entries)...\n", total_fwd);
    int idx = 0;
    for (int a = 1; a <= 127; a++) {
        uint32_t r1 = hash_round(0, a);
        for (int b = 1; b <= 127; b++) {
            uint32_t r2 = hash_round(r1, b);
            for (int c = 1; c <= 127; c++) {
                uint32_t h = hash_round(r2, c);
                struct entry *e = &pool[idx++];
                e->hash = h; e->a = a; e->b = b; e->c = c;
                uint32_t slot = h & (HT_SIZE - 1);
                e->next = ht[slot];
                ht[slot] = e;
            }
        }
        if (a % 16 == 0) printf("  fwd: %d/127\n", a);
    }
    printf("  done (%d entries)\n", idx);

    uint8_t pwd[PWDLEN];
    int suffix_len = PWDLEN - 3;
    uint8_t *suffix = malloc(suffix_len);
    if (!suffix) { perror("malloc"); return 1; }

    long long attempts = 0;
    while (1) {
        uint32_t r = TARGET;
        for (int i = suffix_len - 1; i >= 0; i--) {
            uint8_t c = (rand() % 127) + 1;
            suffix[i] = c;
            r = inv_hash_round(r, c);
        }
        memcpy(&pwd[3], suffix, suffix_len);

        attempts++;
        uint32_t slot = r & (HT_SIZE - 1);
        for (struct entry *e = ht[slot]; e; e = e->next) {
            if (e->hash == r) {
                pwd[0] = e->a;
                pwd[1] = e->b;
                pwd[2] = e->c;

                uint32_t r_test = 0;
                for (int i = 0; i < PWDLEN; i++)
                    r_test = hash_round(r_test, pwd[i]);
                if (r_test == TARGET) {
                    printf("Found after %lld attempts, password length %d:\n", attempts, PWDLEN);
                    for (int i = 0; i < PWDLEN; i++)
                        printf("\\x%02x", pwd[i]);
                    printf("\n");
                    printf("static const uint8_t password[] = {");
                    for (int i = 0; i < PWDLEN; i++)
                        printf("%s0x%02x", i ? ", " : "", pwd[i]);
                    printf(", 0};\n");
                    free(ht); free(pool); free(suffix);
                    return 0;
                }
            }
        }

        if (attempts % 10000 == 0)
            printf("  attempts: %lld\r", attempts);
    }
}
