#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

uint32_t hash_round(uint32_t r, uint8_t c) {
    r += c;
    r *= 1025;
    r ^= (r >> 6);
    r ^= c;
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
    return r1;
}

#define TARGET 716661863u
#define PWDLEN 100  // 100-char password for wide race window

int main() {
    uint8_t pwd[PWDLEN + 1] = {0};
    
    // Step 1: go backwards from target for (PWDLEN-1) steps with random chars
    uint32_t r = TARGET;
    for (int i = 0; i < PWDLEN - 1; i++) {
        uint8_t c = (rand() % 255) + 1;
        pwd[PWDLEN - 1 - i] = c;
        r = inv_hash_round(r, c);
    }
    
    // Step 2: find final char that connects r to hash_round(0, c)
    for (int c = 1; c < 256; c++) {
        if (hash_round(0, c) == r) {
            pwd[0] = c;
            // Verify
            uint32_t r_test = 0;
            for (int i = 0; i < PWDLEN; i++)
                r_test = hash_round(r_test, pwd[i]);
            if (r_test == TARGET) {
                printf("Password length %d:\n", PWDLEN);
                for (int i = 0; i < PWDLEN; i++)
                    printf("\\x%02x", pwd[i]);
                printf("\n\nC array:\nstatic const uint8_t password[] = {");
                for (int i = 0; i < PWDLEN; i++) {
                    if (i > 0) printf(", ");
                    printf("0x%02x", pwd[i]);
                }
                printf(", 0};\n");
                return 0;
            }
        }
    }
    printf("Failed to find connecting char (very unlikely)\n");
    return 1;
}
