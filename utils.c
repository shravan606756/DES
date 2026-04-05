#include <ctype.h>
#include "des.h"

void hex_to_bin(const char *hex, int *bin)
{
    for (int i = 0; i < 16; i++) {
        unsigned char c = (unsigned char)hex[i];
        int v;
        if      (c >= 'a' && c <= 'f') v = c - 'a' + 10;
        else if (c >= 'A' && c <= 'F') v = c - 'A' + 10;
        else                            v = c - '0';
        for (int j = 3; j >= 0; j--)
            bin[i * 4 + (3 - j)] = (v >> j) & 1;
    }
}

void bin_to_hex(const int *bin, char *hex)
{
    for (int i = 0; i < 16; i++) {
        int val = 0;
        for (int j = 0; j < 4; j++)
            val = (val << 1) | bin[i * 4 + j];
        hex[i] = (val < 10) ? (char)('0' + val) : (char)('A' + val - 10);
    }
    hex[16] = '\0';
}

void permute(const int *in, int *out, const int *t, int n)
{
    for (int i = 0; i < n; i++) out[i] = in[t[i] - 1];
}

void shift_left(int *k, int s)
{
    while (s--) {
        int t = k[0];
        for (int i = 0; i < 27; i++) k[i] = k[i + 1];
        k[27] = t;
    }
}

void xor_bits(const int *a, const int *b, int *o, int n)
{
    for (int i = 0; i < n; i++) o[i] = a[i] ^ b[i];
}

void reverse_keys(int k[16][48])
{
    for (int i = 0; i < 8; i++) {
        for (int j = 0; j < 48; j++) {
            int t    = k[i][j];
            k[i][j]      = k[15 - i][j];
            k[15 - i][j] = t;
        }
    }
}
