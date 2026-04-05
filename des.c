#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "des.h"
#include "tables.h"

/* ── S-box substitution ──────────────────────────────────── */
static void sbox_sub(const int *in, int *out)
{
    int k = 0;
    for (int i = 0; i < 8; i++) {
        int r = in[i * 6] * 2 + in[i * 6 + 5];
        int c = in[i * 6 + 1] * 8 + in[i * 6 + 2] * 4
              + in[i * 6 + 3] * 2 + in[i * 6 + 4];
        int v = sbox[i][r][c];
        for (int j = 3; j >= 0; j--) out[k++] = (v >> j) & 1;
    }
}

/* ── Key schedule ─────────────────────────────────────────── */
void generate_keys(const int *key, int keys[16][48])
{
    int t[56], C[28], D[28];

    permute(key, t, PC1, 56);
    for (int i = 0; i < 28; i++) C[i] = t[i], D[i] = t[i + 28];

    for (int i = 0; i < 16; i++) {
        shift_left(C, shift_table[i]);
        shift_left(D, shift_table[i]);

        int CD[56];
        for (int j = 0; j < 28; j++) CD[j] = C[j], CD[j + 28] = D[j];
        permute(CD, keys[i], PC2, 48);
    }
}

/* ── Core DES block ───────────────────────────────────────── */
void des_block(const int *pt, int keys[16][48], int *ct)
{
    int ip[64];
    permute(pt, ip, IP, 64);

    int L[32], R[32];
    for (int i = 0; i < 32; i++) L[i] = ip[i], R[i] = ip[i + 32];

    for (int i = 0; i < 16; i++) {
        int e[48], x[48], s[32], f[32], nr[32];

        permute(R, e, E, 48);
        xor_bits(e, keys[i], x, 48);
        sbox_sub(x, s);
        permute(s, f, P, 32);
        xor_bits(L, f, nr, 32);

        for (int j = 0; j < 32; j++) L[j] = R[j], R[j] = nr[j];
    }

    int RL[64];
    for (int i = 0; i < 32; i++) RL[i] = R[i], RL[i + 32] = L[i];
    permute(RL, ct, FP, 64);
}

/* ── Internal helpers ─────────────────────────────────────── */

/* 8 raw bytes → 16-char uppercase hex, NUL-terminated. */
static void bytes_to_hex16(const unsigned char *b, char *hex)
{
    static const char H[] = "0123456789ABCDEF";
    for (int i = 0; i < 8; i++) {
        hex[i * 2]     = H[b[i] >> 4];
        hex[i * 2 + 1] = H[b[i] & 0xF];
    }
    hex[16] = '\0';
}

/* 16-char hex → 8 raw bytes. Handles upper- and lower-case. */
static void hex16_to_bytes(const char *hex, unsigned char *b)
{
    for (int i = 0; i < 8; i++) {
        unsigned char hi = (unsigned char)hex[i * 2];
        unsigned char lo = (unsigned char)hex[i * 2 + 1];
        int h = (hi >= 'a') ? hi - 'a' + 10 : (hi >= 'A') ? hi - 'A' + 10 : hi - '0';
        int l = (lo >= 'a') ? lo - 'a' + 10 : (lo >= 'A') ? lo - 'A' + 10 : lo - '0';
        b[i] = (unsigned char)((h << 4) | l);
    }
}

/* ── High-level API ──────────────────────────────────────── */

int des_block_hex(const char *in_hex, const char *key_hex,
                  int decrypt, char out_hex[17])
{
    int block[64], key_bits[64], out[64];
    int keys[16][48];

    hex_to_bin(in_hex,  block);
    hex_to_bin(key_hex, key_bits);
    generate_keys(key_bits, keys);
    if (decrypt) reverse_keys(keys);
    des_block(block, keys, out);
    bin_to_hex(out, out_hex);
    return 0;
}

char *des_ecb_encrypt(const char *plaintext, const char *key_hex)
{
    size_t len = strlen(plaintext);

    /* PKCS#7: always append at least 1 byte of padding (max 8). */
    size_t padded_len = (len / 8 + 1) * 8;
    unsigned char *padded = (unsigned char *)malloc(padded_len);
    if (!padded) return NULL;

    memcpy(padded, plaintext, len);
    unsigned char pad_byte = (unsigned char)(padded_len - len);
    for (size_t i = len; i < padded_len; i++) padded[i] = pad_byte;

    /* Build key schedule. */
    int key_bits[64], keys[16][48];
    char key_upper[17];
    for (int i = 0; i < 16; i++)
        key_upper[i] = (char)toupper((unsigned char)key_hex[i]);
    key_upper[16] = '\0';
    hex_to_bin(key_upper, key_bits);
    generate_keys(key_bits, keys);

    size_t num_blocks = padded_len / 8;
    char *cipher_hex = (char *)malloc(num_blocks * 16 + 1);
    if (!cipher_hex) { free(padded); return NULL; }

    for (size_t b = 0; b < num_blocks; b++) {
        char  blk_hex_in[17], blk_hex_out[17];
        int   blk_bits[64], out_bits[64];

        bytes_to_hex16(padded + b * 8, blk_hex_in);
        hex_to_bin(blk_hex_in, blk_bits);
        des_block(blk_bits, keys, out_bits);
        bin_to_hex(out_bits, blk_hex_out);
        memcpy(cipher_hex + b * 16, blk_hex_out, 16);
    }
    cipher_hex[num_blocks * 16] = '\0';
    free(padded);
    return cipher_hex;
}

char *des_ecb_decrypt(const char *cipher_hex, const char *key_hex)
{
    size_t hex_len = strlen(cipher_hex);
    if (hex_len == 0 || hex_len % 16 != 0) return NULL;

    /* Build key schedule (reversed for decryption). */
    int key_bits[64], keys[16][48];
    char key_upper[17];
    for (int i = 0; i < 16; i++)
        key_upper[i] = (char)toupper((unsigned char)key_hex[i]);
    key_upper[16] = '\0';
    hex_to_bin(key_upper, key_bits);
    generate_keys(key_bits, keys);
    reverse_keys(keys);

    size_t num_blocks = hex_len / 16;
    unsigned char *plain = (unsigned char *)malloc(num_blocks * 8 + 1);
    if (!plain) return NULL;

    for (size_t b = 0; b < num_blocks; b++) {
        char  blk_hex_in[17], blk_hex_out[17];
        int   blk_bits[64], out_bits[64];

        /* Normalize to uppercase. */
        for (int i = 0; i < 16; i++)
            blk_hex_in[i] = (char)toupper((unsigned char)cipher_hex[b * 16 + i]);
        blk_hex_in[16] = '\0';

        hex_to_bin(blk_hex_in, blk_bits);
        des_block(blk_bits, keys, out_bits);
        bin_to_hex(out_bits, blk_hex_out);
        hex16_to_bytes(blk_hex_out, plain + b * 8);
    }

    /* Strip PKCS#7 padding. */
    unsigned char pad = plain[num_blocks * 8 - 1];
    if (pad >= 1 && pad <= 8) {
        int valid = 1;
        for (size_t i = num_blocks * 8 - pad; i < num_blocks * 8; i++)
            if (plain[i] != pad) { valid = 0; break; }
        plain[valid ? num_blocks * 8 - pad : num_blocks * 8] = '\0';
    } else {
        plain[num_blocks * 8] = '\0';
    }

    return (char *)plain;
}
