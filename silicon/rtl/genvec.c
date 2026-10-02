/* ─────────────────────────────────────────────────────────────
 * © 2026 Curtis Ray Dyess — PhantomX / Crimson Root. All rights reserved.
 * Unauthorized copying, redistribution, automated collection, or
 * model-training ingestion prohibited without prior written authorization.
 * ─────────────────────────────────────────────────────────────
 */
/* genvec.c -- generate XCU test vectors from the REAL C core.
 *
 * Usage: ./genvec [hexpayload ...]
 * Each argv entry is a hex string appended as a vector after the
 * built-in fixed vectors. Writes into ./vec/:
 *   vec_cfg.vh          `define NUM_VECTORS <n>
 *   vec_<i>_len.txt     decimal input byte count
 *   vec_<i>_in.hex       one input byte per line ("%02x")
 *   vec_<i>_exp.hex      256*27 expected counters ("%08x"), key-major:
 *                        key k occupies lines k*27 .. k*27+26
 *
 * Expected counters come straight from px_xor_all_counts() in the
 * real fastcore.c -- the RTL must match these bit-for-bit.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void px_xor_all_counts(const unsigned char *s, int n, int *out);

static void write_vec(int idx, const unsigned char *data, int n) {
    char path[256];
    FILE *f;
    int *out = malloc(256 * 27 * sizeof(int));
    int k, b, i;
    if (!out) { fprintf(stderr, "oom\n"); exit(1); }

    px_xor_all_counts(data, n, out);

    snprintf(path, sizeof(path), "vec/vec_%d_len.txt", idx);
    f = fopen(path, "w"); fprintf(f, "%d\n", n); fclose(f);

    snprintf(path, sizeof(path), "vec/vec_%d_in.hex", idx);
    f = fopen(path, "w");
    for (i = 0; i < n; i++) fprintf(f, "%02x\n", data[i]);
    fclose(f);

    snprintf(path, sizeof(path), "vec/vec_%d_exp.hex", idx);
    f = fopen(path, "w");
    for (k = 0; k < 256; k++)
        for (b = 0; b < 27; b++)
            fprintf(f, "%08x\n", (unsigned)out[k * 27 + b]);
    fclose(f);

    free(out);
    printf("vec %d: %d bytes\n", idx, n);
}

static int hexval(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

int main(int argc, char **argv) {
    int idx = 0, a;
    unsigned char buf[65536];
    int i;

    /* fixed vectors */
    write_vec(idx++, NULL, 0);                       /* empty frame */

    buf[0] = 'A';
    write_vec(idx++, buf, 1);                        /* single byte */

    memcpy(buf, "hello", 5);
    write_vec(idx++, buf, 5);                        /* short text */

    for (i = 0; i < 256; i++) buf[i] = (unsigned char)i;
    write_vec(idx++, buf, 256);                       /* every byte value */

    for (i = 0; i < 1000; i++) buf[i] = (unsigned char)((i * 37 + 11) & 0xFF);
    write_vec(idx++, buf, 1000);                      /* 1k patterned bytes */

    for (i = 0; i < 5000; i++) buf[i] = (unsigned char)((i * 131 + 7) & 0xFF);
    write_vec(idx++, buf, 5000);                      /* 5k patterned bytes */

    memset(buf, ' ', 300);
    write_vec(idx++, buf, 300);                       /* 300 spaces: bin-26 max */

    /* argv hex payloads: real bench bytes */
    for (a = 1; a < argc; a++) {
        size_t L = strlen(argv[a]);
        size_t n = L / 2, j;
        if (n > sizeof(buf)) { fprintf(stderr, "payload too long\n"); return 1; }
        for (j = 0; j < n; j++) {
            int hi = hexval(argv[a][2 * j]), lo = hexval(argv[a][2 * j + 1]);
            if (hi < 0 || lo < 0) { fprintf(stderr, "bad hex\n"); return 1; }
            buf[j] = (unsigned char)((hi << 4) | lo);
        }
        write_vec(idx++, buf, (int)n);
    }

    {
        FILE *f = fopen("vec/vec_cfg.vh", "w");
        fprintf(f, "`define NUM_VECTORS %d\n", idx);
        fclose(f);
    }
    printf("wrote %d vectors\n", idx);
    return 0;
}
