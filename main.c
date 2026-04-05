#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include "des.h"

static int is_hex_16(const char *s)
{
    if (strlen(s) != 16) return 0;
    for (int i = 0; i < 16; i++)
    {
        if (!isxdigit((unsigned char)s[i])) return 0;
    }
    return 1;
}

static void normalize_upper_hex(char *s)
{
    for (int i = 0; i < 16; i++) s[i] = (char)toupper((unsigned char)s[i]);
}

static void print_usage(const char *prog)
{
    printf("Usage:\n");
    printf("  %s -e <16-hex-plaintext> <16-hex-key>\n", prog);
    printf("  %s -d <16-hex-ciphertext> <16-hex-key>\n", prog);
    printf("  %s\n", prog);
    printf("\nIf no arguments are provided, plaintext/ciphertext and key are read from stdin.\n");
}

int main(int argc, char **argv)
{
    char block_hex[17] = {0};
    char key_hex[17] = {0};
    int block[64], key[64], out[64];
    int keys[16][48];
    int decrypt = 0;

    if (argc == 4)
    {
        if (strcmp(argv[1], "-e") == 0 || strcmp(argv[1], "--encrypt") == 0)
        {
            decrypt = 0;
        }
        else if (strcmp(argv[1], "-d") == 0 || strcmp(argv[1], "--decrypt") == 0)
        {
            decrypt = 1;
        }
        else
        {
            print_usage(argv[0]);
            return 1;
        }

        strncpy(block_hex, argv[2], 16);
        strncpy(key_hex, argv[3], 16);
        block_hex[16] = '\0';
        key_hex[16] = '\0';
    }
    else if (argc == 1)
    {
        if (scanf("%16s", block_hex) != 1 || scanf("%16s", key_hex) != 1)
        {
            fprintf(stderr, "Input error: expected 2 hex strings of length 16.\n");
            return 1;
        }
    }
    else
    {
        print_usage(argv[0]);
        return 1;
    }

    if (!is_hex_16(block_hex) || !is_hex_16(key_hex))
    {
        fprintf(stderr, "Validation error: block and key must be exactly 16 hex characters.\n");
        return 1;
    }

    normalize_upper_hex(block_hex);
    normalize_upper_hex(key_hex);

    hex_to_bin(block_hex, block);
    hex_to_bin(key_hex, key);

    generate_keys(key, keys);
    if (decrypt) reverse_keys(keys);

    des_block(block, keys, out);

    for (int i = 0; i < 64; i++) printf("%d", out[i]);
    printf("\n");

    return 0;
}