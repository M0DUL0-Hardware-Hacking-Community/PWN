#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

uint32_t hash(const uint8_t *s) {
    uint32_t r = 0;
    while (*s) {
        uint8_t c = *s;
        r += c;
        r += r << 10;
        r ^= r >> 6;
        r ^= c;
        s++;
    }
    return r;
}

int main(int argc, char **argv) {
    uint32_t target;
    if (argc > 1) target = strtoul(argv[1], NULL, 0);
    else target = 716789863;

    printf("Searching for preimage of %u (0x%x)\n", target, target);
    printf("Testing: 1-4 char strings (no null bytes)\n");

    uint8_t buf[8] = {0};

    // 1 char
    for (uint32_t a = 1; a < 256; a++) {
        buf[0] = a; buf[1] = 0;
        if (hash(buf) == target) {
            printf("Found: 1-char: '\\x%02x'\n", a);
            printf("Verify: hash=%u\n", hash(buf));
            return 0;
        }
    }
    printf("1-char done\n");

    // 2 chars
    for (uint32_t a = 1; a < 256; a++) {
        buf[0] = a;
        for (uint32_t b = 1; b < 256; b++) {
            buf[1] = b; buf[2] = 0;
            if (hash(buf) == target) {
                printf("Found: 2-char: '\\x%02x\\x%02x'\n", a, b);
                printf("Verify: hash=%u\n", hash(buf));
                return 0;
            }
        }
    }
    printf("2-char done\n");

    // 3 chars
    for (uint32_t a = 1; a < 256; a++) {
        buf[0] = a;
        for (uint32_t b = 1; b < 256; b++) {
            buf[1] = b;
            for (uint32_t c = 1; c < 256; c++) {
                buf[2] = c; buf[3] = 0;
                if (hash(buf) == target) {
                    printf("Found: 3-char: '\\x%02x\\x%02x\\x%02x'\n", a, b, c);
                    printf("Verify: hash=%u\n", hash(buf));
                    return 0;
                }
            }
        }
    }
    printf("3-char done (not found)\n");

    // 4 chars
    for (uint32_t a = 1; a < 256; a++) {
        buf[0] = a;
        if (a % 16 == 0) printf("  progress: a=%d/255\n", a);
        for (uint32_t b = 1; b < 256; b++) {
            buf[1] = b;
            for (uint32_t c = 1; c < 256; c++) {
                buf[2] = c;
                for (uint32_t d = 1; d < 256; d++) {
                    buf[3] = d; buf[4] = 0;
                    if (hash(buf) == target) {
                        printf("Found: 4-char: '\\x%02x\\x%02x\\x%02x\\x%02x'\n", a, b, c, d);
                        printf("Verify: hash=%u\n", hash(buf));
                        return 0;
                    }
                }
            }
        }
    }
    printf("4-char done (not found)\n");
    return 1;
}
