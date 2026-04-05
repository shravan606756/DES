#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include "des.h"

#define VERSION "1.0.0"
#define MAX_INPUT 4096

/* ── ANSI colour helpers (auto-disabled on non-tty stdout) ── */
static int color_on = 0;

#define C_RESET  (color_on ? "\033[0m"   : "")
#define C_BOLD   (color_on ? "\033[1m"   : "")
#define C_DIM    (color_on ? "\033[2m"   : "")
#define C_RED    (color_on ? "\033[31m"  : "")
#define C_GREEN  (color_on ? "\033[32m"  : "")
#define C_YELLOW (color_on ? "\033[33m"  : "")
#define C_CYAN   (color_on ? "\033[36m"  : "")

/* ── Validation helpers ──────────────────────────────────── */
static int is_hex_n(const char *s, size_t n)
{
    if (strlen(s) != n) return 0;
    for (size_t i = 0; i < n; i++)
        if (!isxdigit((unsigned char)s[i])) return 0;
    return 1;
}

static void str_to_upper(char *s, size_t n)
{
    for (size_t i = 0; i < n; i++)
        s[i] = (char)toupper((unsigned char)s[i]);
}

/* ── Banner ──────────────────────────────────────────────── */
static void print_banner(void)
{
    printf("%s%s"
           "  ╔════════════════════════════════╗\n"
           "  ║   DES Encryption Tool  v%-6s  ║\n"
           "  ╚════════════════════════════════╝%s\n\n",
           C_BOLD, C_CYAN, VERSION, C_RESET);
}

/* ── Usage ───────────────────────────────────────────────── */
static void print_usage(const char *prog)
{
    print_banner();
    printf("%s%sUSAGE%s\n", C_BOLD, C_YELLOW, C_RESET);
    printf("  %s [OPTIONS] -e <text>  <16-hex-key>   encrypt\n", prog);
    printf("  %s [OPTIONS] -d <hex>   <16-hex-key>   decrypt\n", prog);
    printf("  %s                                     interactive mode\n\n", prog);

    printf("%s%sOPTIONS%s\n", C_BOLD, C_YELLOW, C_RESET);
    printf("  %s-e%s, %s--encrypt%s     encrypt text  →  ECB+PKCS#7 hex ciphertext\n",
           C_GREEN, C_RESET, C_GREEN, C_RESET);
    printf("  %s-d%s, %s--decrypt%s     decrypt hex ciphertext  →  plaintext\n",
           C_GREEN, C_RESET, C_GREEN, C_RESET);
    printf("  %s    --hex%s         raw 64-bit block mode (16-char hex I/O)\n",
           C_GREEN, C_RESET);
    printf("  %s-v%s, %s--verbose%s     print the 16-round key schedule\n",
           C_GREEN, C_RESET, C_GREEN, C_RESET);
    printf("  %s-q%s, %s--quiet%s       output result only (no labels or colours)\n",
           C_GREEN, C_RESET, C_GREEN, C_RESET);
    printf("  %s    --version%s     show version and exit\n", C_GREEN, C_RESET);
    printf("  %s-h%s, %s--help%s        show this message and exit\n\n",
           C_GREEN, C_RESET, C_GREEN, C_RESET);

    printf("%s%sEXAMPLES%s\n", C_BOLD, C_YELLOW, C_RESET);
    printf("  %s# Encrypt a text string (ECB mode, PKCS#7 padding)%s\n", C_DIM, C_RESET);
    printf("  %s -e \"Hello, World!\" 133457799BBCDFF1\n\n", prog);
    printf("  %s# Decrypt hex ciphertext%s\n", C_DIM, C_RESET);
    printf("  %s -d 85E813540F0AB405D9F1CF3B 133457799BBCDFF1\n\n", prog);
    printf("  %s# Single 64-bit block (raw hex)%s\n", C_DIM, C_RESET);
    printf("  %s --hex -e 0123456789ABCDEF 133457799BBCDFF1\n\n", prog);
    printf("  %s# Pipe mode – one line of input, one line of key%s\n", C_DIM, C_RESET);
    printf("  printf 'Hello\\n133457799BBCDFF1\\n' | %s -e\n\n", prog);
}

/* ── Key-schedule display (verbose mode) ─────────────────── */
static void print_key_schedule(const char *key_hex)
{
    int key_bits[64], keys[16][48];
    char key_upper[17];

    for (int i = 0; i < 16; i++)
        key_upper[i] = (char)toupper((unsigned char)key_hex[i]);
    key_upper[16] = '\0';

    hex_to_bin(key_upper, key_bits);
    generate_keys(key_bits, keys);

    printf("\n%s%sKEY SCHEDULE%s\n", C_BOLD, C_YELLOW, C_RESET);
    for (int i = 0; i < 16; i++) {
        printf("  %sK%-2d%s: ", C_CYAN, i + 1, C_RESET);
        for (int j = 0; j < 48; j += 4) {
            int nibble = keys[i][j] * 8 + keys[i][j + 1] * 4
                       + keys[i][j + 2] * 2 + keys[i][j + 3];
            printf("%X", nibble);
        }
        printf("\n");
    }
    printf("\n");
}

/* ── Pretty result display ───────────────────────────────── */
static void print_result(int decrypt, int hex_mode,
                         const char *key_hex,
                         const char *input, const char *output)
{
    const char *in_lbl  = decrypt ? "Ciphertext" : "Plaintext ";
    const char *out_lbl = decrypt ? "Plaintext " : "Ciphertext";
    const char *mode    = decrypt ? "DECRYPT"    : "ENCRYPT";
    const char *algo    = hex_mode ? "single 64-bit block"
                                   : "ECB / PKCS#7";

    printf("\n");
    printf("  %s%sMode%s  : %s%s%s  %s(%s)%s\n",
           C_BOLD, C_CYAN, C_RESET,
           C_BOLD, mode, C_RESET,
           C_DIM, algo, C_RESET);
    printf("  %s%sKey%s   : %s%s%s\n",
           C_BOLD, C_CYAN, C_RESET, C_YELLOW, key_hex, C_RESET);
    printf("  %s%s%s%s: %s\n",
           C_BOLD, C_CYAN, in_lbl, C_RESET, input);
    printf("  %s────────────────────────────────────────────%s\n",
           C_DIM, C_RESET);
    printf("  %s%s%s%s: %s%s%s\n\n",
           C_BOLD, C_CYAN, out_lbl, C_RESET,
           C_GREEN, output, C_RESET);
}

/* ── Interactive mode (tty, no arguments) ────────────────── */
static void interactive_mode(void)
{
    char  mode_str[16]          = {0};
    char  input[MAX_INPUT + 1]  = {0};
    char  key_hex[17]           = {0};
    int   decrypt               = 0;

    print_banner();

    printf("%sMode%s (encrypt / decrypt): ", C_CYAN, C_RESET);
    fflush(stdout);
    if (scanf("%15s", mode_str) != 1) goto err;
    if (strcmp(mode_str, "decrypt") == 0 || strcmp(mode_str, "d") == 0)
        decrypt = 1;

    /* Consume remainder of current line. */
    { int c; while ((c = getchar()) != '\n' && c != EOF); }

    printf("%s%s%s: ",
           C_CYAN,
           decrypt ? "Ciphertext (hex)" : "Plaintext (text)",
           C_RESET);
    fflush(stdout);
    if (!fgets(input, sizeof(input), stdin)) goto err;
    { size_t l = strlen(input); if (l > 0 && input[l-1] == '\n') input[l-1] = '\0'; }

    printf("%sKey%s (16 hex chars): ", C_CYAN, C_RESET);
    fflush(stdout);
    if (scanf("%16s", key_hex) != 1) goto err;

    if (!is_hex_n(key_hex, 16)) {
        fprintf(stderr, "%serror%s: key must be exactly 16 hex characters.\n",
                C_RED, C_RESET);
        return;
    }
    str_to_upper(key_hex, 16);

    if (decrypt) {
        size_t hlen = strlen(input);
        if (!is_hex_n(input, hlen) || hlen % 16 != 0) {
            fprintf(stderr, "%serror%s: ciphertext must be a hex string "
                    "whose length is a multiple of 16.\n", C_RED, C_RESET);
            return;
        }
        str_to_upper(input, hlen);
        char *result = des_ecb_decrypt(input, key_hex);
        if (!result) { fprintf(stderr, "%serror%s: decryption failed.\n", C_RED, C_RESET); return; }
        print_result(1, 0, key_hex, input, result);
        free(result);
    } else {
        char *result = des_ecb_encrypt(input, key_hex);
        if (!result) { fprintf(stderr, "%serror%s: encryption failed.\n", C_RED, C_RESET); return; }
        print_result(0, 0, key_hex, input, result);
        free(result);
    }
    return;
err:
    fprintf(stderr, "%serror%s: failed to read input.\n", C_RED, C_RESET);
}

/* ── main ────────────────────────────────────────────────── */
int main(int argc, char **argv)
{
    color_on = isatty(STDOUT_FILENO);

    int         decrypt    = 0;
    int         hex_mode   = 0;
    int         verbose    = 0;
    int         quiet      = 0;
    int         mode_set   = 0;
    const char *input      = NULL;
    const char *key_arg    = NULL;
    char        key_hex[17]          = {0};
    char        stdin_buf[MAX_INPUT + 1] = {0};
    char        stdin_key[17]        = {0};

    /* ── No arguments ─── */
    if (argc == 1) {
        if (isatty(STDIN_FILENO)) {
            interactive_mode();
        } else {
            print_usage(argv[0]);
        }
        return 0;
    }

    /* ── Parse flags and positional arguments ─── */
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            print_usage(argv[0]);
            return 0;
        }
        if (strcmp(argv[i], "--version") == 0) {
            printf("%sDES%s v%s — Data Encryption Standard (FIPS 46-3)\n",
                   C_BOLD, C_RESET, VERSION);
            printf("ECB mode with PKCS#7 padding | raw hex-block mode\n");
            return 0;
        }
        if (strcmp(argv[i], "-e") == 0 || strcmp(argv[i], "--encrypt") == 0) {
            decrypt = 0; mode_set = 1; continue;
        }
        if (strcmp(argv[i], "-d") == 0 || strcmp(argv[i], "--decrypt") == 0) {
            decrypt = 1; mode_set = 1; continue;
        }
        if (strcmp(argv[i], "--hex") == 0)                           { hex_mode = 1; continue; }
        if (strcmp(argv[i], "-v") == 0 || strcmp(argv[i], "--verbose") == 0) { verbose  = 1; continue; }
        if (strcmp(argv[i], "-q") == 0 || strcmp(argv[i], "--quiet")   == 0) { quiet    = 1; continue; }

        /* Positional arguments */
        if (!input)   { input   = argv[i]; continue; }
        if (!key_arg) { key_arg = argv[i]; continue; }
        fprintf(stderr, "%serror%s: unexpected argument '%s'.\n",
                C_RED, C_RESET, argv[i]);
        return 1;
    }

    if (!mode_set) {
        fprintf(stderr, "%serror%s: specify -e (encrypt) or -d (decrypt).\n",
                C_RED, C_RESET);
        print_usage(argv[0]);
        return 1;
    }

    /* ── Read from stdin if positional args are missing ─── */
    if (!input || !key_arg) {
        if (hex_mode) {
            /* Expect:  <16-hex-block> <16-hex-key>  (whitespace separated) */
            if (scanf("%4096s %16s", stdin_buf, stdin_key) != 2) {
                fprintf(stderr, "%serror%s: expected '<16-hex-block> <16-hex-key>' on stdin.\n",
                        C_RED, C_RESET);
                return 1;
            }
        } else {
            /* Expect:  first line = text/ciphertext,  second line = key */
            if (!fgets(stdin_buf, sizeof(stdin_buf), stdin)) {
                fprintf(stderr, "%serror%s: failed to read input from stdin.\n",
                        C_RED, C_RESET);
                return 1;
            }
            { size_t l = strlen(stdin_buf); if (l > 0 && stdin_buf[l-1] == '\n') stdin_buf[l-1] = '\0'; }
            if (scanf("%16s", stdin_key) != 1) {
                fprintf(stderr, "%serror%s: failed to read key from stdin.\n",
                        C_RED, C_RESET);
                return 1;
            }
        }
        if (!input)   input   = stdin_buf;
        if (!key_arg) key_arg = stdin_key;
    }

    /* ── Validate key ─── */
    if (!is_hex_n(key_arg, 16)) {
        fprintf(stderr, "%serror%s: key must be exactly 16 hex characters.\n",
                C_RED, C_RESET);
        return 1;
    }
    memcpy(key_hex, key_arg, 16);
    key_hex[16] = '\0';
    str_to_upper(key_hex, 16);

    /* ── Verbose: key schedule ─── */
    if (verbose) print_key_schedule(key_hex);

    /* ── Run DES ─── */
    if (hex_mode) {
        /* Single 64-bit block */
        if (!is_hex_n(input, 16)) {
            fprintf(stderr, "%serror%s: --hex mode requires exactly 16 hex "
                    "characters for the block.\n", C_RED, C_RESET);
            return 1;
        }
        char in_hex[17];
        memcpy(in_hex, input, 16);
        in_hex[16] = '\0';
        str_to_upper(in_hex, 16);

        char out_hex[17];
        des_block_hex(in_hex, key_hex, decrypt, out_hex);

        if (!quiet && color_on)
            print_result(decrypt, 1, key_hex, in_hex, out_hex);
        else
            printf("%s\n", out_hex);

    } else {
        /* ECB text mode */
        char *result = NULL;

        if (!decrypt) {
            result = des_ecb_encrypt(input, key_hex);
        } else {
            size_t hlen = strlen(input);
            int valid_hex = 1;
            for (size_t i = 0; i < hlen; i++)
                if (!isxdigit((unsigned char)input[i])) { valid_hex = 0; break; }

            if (!valid_hex || hlen % 16 != 0) {
                fprintf(stderr, "%serror%s: ciphertext must be a hex string "
                        "whose length is a multiple of 16.\n", C_RED, C_RESET);
                return 1;
            }
            char *hex_copy = (char *)malloc(hlen + 1);
            if (!hex_copy) { fprintf(stderr, "error: out of memory.\n"); return 1; }
            memcpy(hex_copy, input, hlen + 1);
            str_to_upper(hex_copy, hlen);
            result = des_ecb_decrypt(hex_copy, key_hex);
            free(hex_copy);
        }

        if (!result) {
            fprintf(stderr, "%serror%s: DES operation failed.\n", C_RED, C_RESET);
            return 1;
        }

        if (!quiet && color_on)
            print_result(decrypt, 0, key_hex, input, result);
        else
            printf("%s\n", result);

        free(result);
    }

    return 0;
}
