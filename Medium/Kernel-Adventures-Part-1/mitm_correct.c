#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#define TARGET 716661863

// Forward hash
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

// Inverse of x ^ (x >> 6)
uint32_t inv_xor_shift_6(uint32_t y) {
    uint32_t x = y & 0xfc000000;
    for (int i = 25; i >= 0; i--) {
        uint32_t bit = ((y >> i) ^ (x >> (i + 6))) & 1;
        x |= (bit << i);
    }
    return x;
}

#define INV_1025 3222273025u

// Inverse of hash_round: given r_out and c, find r_in
uint32_t inv_hash_round(uint32_t r_out, uint8_t c) {
    uint32_t r_temp = r_out ^ c;
    uint32_t x = inv_xor_shift_6(r_temp);
    uint32_t r1 = x * INV_1025;
    uint32_t r_in = r1 - c;
    return r_in;
}

int main() {
    printf("MITM: finding 5-char preimage for %u (0x%x)\n", TARGET, TARGET);
    printf("Phase 1: build 2-char forward table (65K entries)\n");
    
    // Phase 1: 2-char forward
    // We'll store in a hash table for fast lookup
    // Since N=65K, a simple array indexed by hash would be 4GB (too big)
    // Use a hash map: 2^18 = 262K entries, chaining
    
    #define HT_SIZE 262144
    #define HT_MASK (HT_SIZE - 1)
    
    struct entry {
        uint32_t hash;
        uint8_t c1, c2;
        struct entry *next;
    };
    
    struct entry *ht[HT_SIZE] = {0};
    struct entry *pool = calloc(255 * 255, sizeof(struct entry));
    if (!pool) { perror("calloc"); return 1; }
    
    int idx = 0;
    for (int c1 = 1; c1 < 256; c1++) {
        uint32_t r1 = hash_round(0, c1);
        for (int c2 = 1; c2 < 256; c2++) {
            uint32_t h = hash_round(r1, c2);
            struct entry *e = &pool[idx++];
            e->hash = h;
            e->c1 = c1;
            e->c2 = c2;
            uint32_t slot = h & HT_MASK;
            e->next = ht[slot];
            ht[slot] = e;
        }
    }
    printf("  Built %d entries\n", idx);
    
    printf("Phase 2: search 3-char backwards...\n");
    
    uint8_t pwd[8] = {0};
    int found = 0;
    long long count = 0;
    
    for (int c3 = 1; c3 < 256 && !found; c3++) {
        uint32_t r2 = inv_hash_round(TARGET, c3);
        for (int c4 = 1; c4 < 256 && !found; c4++) {
            uint32_t r1 = inv_hash_round(r2, c4);
            for (int c5 = 1; c5 < 256 && !found; c5++) {
                uint32_t r0 = inv_hash_round(r1, c5);
                count++;
                
                // Check if r0 is in HT
                uint32_t slot = r0 & HT_MASK;
                for (struct entry *e = ht[slot]; e; e = e->next) {
                    if (e->hash == r0) {
                        pwd[0] = e->c1;
                        pwd[1] = e->c2;
                        pwd[2] = c3;
                        pwd[3] = c4;
                        pwd[4] = c5;
                        pwd[5] = 0;
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
        printf("Found (after %lld attempts): ", count);
        for (int i = 0; pwd[i]; i++) printf("\\x%02x", pwd[i]);
        printf("\nString: ");
        for (int i = 0; pwd[i]; i++) {
            if (pwd[i] >= 32 && pwd[i] < 127) printf("%c", pwd[i]);
            else printf(".");
        }
        printf("\nVerify hash: %u (expected %u)\n", hash_str(pwd), TARGET);
    } else {
        printf("Not found after %lld attempts\n", count);
    }
    
    free(pool);
    return found ? 0 : 1;
}
