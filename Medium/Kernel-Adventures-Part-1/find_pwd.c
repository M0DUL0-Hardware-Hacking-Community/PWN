#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define TARGET 716661863
#define LENGTH 10

uint32_t hash_round(uint32_t r, uint8_t c) {
    r += c;
    r *= 1025;
    r ^= (r >> 6);
    r ^= c;
    return r;
}

uint32_t inv_xor_shift_6(uint32_t y) {
    uint32_t x = y & 0xfc000000;
    for (int i = 25; i >= 0; i--)
        x |= (((y >> i) ^ (x >> (i + 6))) & 1) << i;
    return x;
}

#define INV_1025 3222273025u

uint32_t inv_hash_round(uint32_t r_out, uint8_t c) {
    uint32_t r_temp = r_out ^ c;
    return (inv_xor_shift_6(r_temp) * INV_1025) - c;
}

int main() {
    uint8_t pwd[256] = {0};
    uint32_t r;
    long long attempts = 0;
    
    printf("Finding %d-char password for target %u (0x%x)...\n", LENGTH, TARGET, TARGET);
    
    srand(12345);
    
    while (1) {
        // Go backwards LENGTH-1 steps from target
        r = TARGET;
        for (int step = 0; step < LENGTH - 1; step++) {
            uint8_t c = (rand() % 255) + 1;
            r = inv_hash_round(r, c);
            pwd[LENGTH - 2 - step] = c;
        }
        
        // Try all final chars
        for (int c = 1; c < 256; c++) {
            if (hash_round(0, c) == r) {
                pwd[0] = c;
                pwd[LENGTH] = 0;
                
                // Verify
                uint32_t r_test = 0;
                for (int i = 0; i < LENGTH; i++)
                    r_test = hash_round(r_test, pwd[i]);
                
                if (r_test == TARGET) {
                    printf("Found after %lld attempts!\n", attempts);
                    printf("Password (%d bytes): ", LENGTH);
                    for (int i = 0; i < LENGTH; i++)
                        printf("\\x%02x", pwd[i]);
                    printf("\n");
                    printf("Verify: hash=%u\n", r_test);
                    return 0;
                }
            }
        }
        
        attempts++;
        if (attempts % 1000000 == 0)
            printf("  attempts: %lld (current_r=0x%08x)\n", attempts, r);
    }
}
