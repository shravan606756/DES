#ifndef DES_H
#define DES_H

#include <stddef.h>

/* ── Bit-array utilities ─────────────────────────────────── */
void hex_to_bin(const char *hex, int *bin);
void bin_to_hex(const int *bin, char *hex);
void permute(const int *in, int *out, const int *t, int n);
void shift_left(int *k, int s);
void xor_bits(const int *a, const int *b, int *o, int n);

/* ── Key schedule ─────────────────────────────────────────── */
void generate_keys(const int *key, int keys[16][48]);
void reverse_keys(int keys[16][48]);

/* ── Core DES block (64-bit bit arrays) ───────────────────── */
void des_block(const int *pt, int keys[16][48], int *ct);

/* ── High-level API (hex strings) ─────────────────────────── */

/*
 * Single 64-bit block: in_hex/key_hex = 16 uppercase hex chars.
 * out_hex must be a caller-provided buffer of at least 17 bytes.
 * decrypt = 0 → encrypt, 1 → decrypt.
 * Returns 0 on success.
 */
int des_block_hex(const char *in_hex, const char *key_hex,
                  int decrypt, char out_hex[17]);

/*
 * ECB-mode text encryption with PKCS#7 padding.
 * plaintext : arbitrary NUL-terminated string.
 * key_hex   : 16 hex characters (case-insensitive).
 * Returns   : heap-allocated uppercase hex string (caller must free),
 *             or NULL on error.
 */
char *des_ecb_encrypt(const char *plaintext, const char *key_hex);

/*
 * ECB-mode text decryption.
 * cipher_hex: hex string whose length is a multiple of 16 (case-insensitive).
 * key_hex   : 16 hex characters (case-insensitive).
 * Returns   : heap-allocated NUL-terminated plaintext (caller must free),
 *             or NULL on error.
 */
char *des_ecb_decrypt(const char *cipher_hex, const char *key_hex);

#endif
