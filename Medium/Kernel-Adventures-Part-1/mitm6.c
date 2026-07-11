#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#define TARGET 716661863

uint32_t hash_round(uint32_t r, uint8_t c) {
    r += c;
    r *= 1025;
    r ^= (r >> 6);
    r ^= c;
    return r;
}

uint32_t hash_str(const uint8_t *s) {
    uint32_t r = 0;
    while (*s) {
        r = hash_round(r, *s);
        s++;
    }
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
    uint32_t r_temp = r_out ^ c;
    uint32_t x = inv_xor_shift_6(r_temp);
    uint32_t r1 = x * INV_1025;
    uint32_t r_in = r1 - c;
    return r_in;
}

int main() {
    printf("MITM 3+3: finding 6-char preimage for %u (0x%x)\n", TARGET, TARGET);
    printf("Phase 1: build 3-char forward table (16.6M entries)...\n");
    
    // 3-char forward: (256-1)^3 = ~16.6M entries
    // Use hash table
    #define HT_SIZE (1 << 22)  // 4M slots
    #define HT_MASK (HT_SIZE - 1)
    
    struct entry { uint32_t hash; uint8_t c[3]; struct entry *next; };
    struct entry *ht[HT_SIZE] = {0};
    
    int total_entries = 255 * 255 * 255;
    struct entry *pool = calloc(total_entries, sizeof(struct entry));
    if (!pool) { perror("calloc"); return 1; }
    
    int idx = 0;
    for (int a = 1; a < 256; a++) {
        uint32_t r1 = hash_round(0, a);
        for (int b = 1; b < 256; b++) {
            uint32_t r2 = hash_round(r1, b);
            for (int c = 1; c < 256; c++) {
                uint32_t h = hash_round(r2, c);
                struct entry *e = &pool[idx++];
                e->hash = h;
                e->c[0] = a; e->c[1] = b; e->c[2] = c;
                uint32_t slot = h & HT_MASK;
                e->next = ht[slot];
                ht[slot] = e;
            }
        }
    }
    printf("  Built %d entries\n", idx);
    
    printf("Phase 2: search 3-char backwards...\n");
    uint8_t pwd[8] = {0};
    int found = 0;
    long long count = 0;
    
    for (int d = 1; d < 256 && !found; d++) {
        uint32_t r3 = inv_hash_round(TARGET, d);
        for (int e = 1; e < 256 && !found; e++) {
            uint32_t r4 = inv_hash_round(r3, e);
            for (int f = 1; f < 256 && !found; f++) {
                uint32_t r5 = inv_hash_round(r4, f);
                count++;
                
                uint32_t slot = r5 & HT_MASK;
                for (struct entry *ent = ht[slot]; ent; ent = ent->next) {
                    if (ent->hash == r5) {
                        pwd[0] = ent->c[0];
                        pwd[1] = ent->c[1];
                        pwd[2] = ent->c[2];
                        pwd[3] = d;
                        pwd[4] = e;
                        pwd[5] = f;
                        pwd[6] = 0;
                        if (hash_str(pwd) == TARGET) {
                            found = 1;
                            break;
                        }
                    }
                }
            }
        }
    }
    
    if (found) {
        printf("Found after %lld attempts:\n  ", count);
        for (int i = 0; pwd[i]; i++) printf("\\x%02x", pwd[i]);
        printf("\n  Verify: hash=%u (expected %u)\n", hash_str(pwd), TARGET);
    } else {
        printf("Not found after %lld attempts\n", count);
    }
    
    free(pool);
    return found ? 0 : 1;
}
