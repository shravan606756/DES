#ifndef DES_H
#define DES_H

void hex_to_bin(char*, int*);
void bin_to_hex(int*, char*);
void permute(int*, int*, int*, int);
void shift_left(int*, int);
void xor(int*, int*, int*, int);

void generate_keys(int*, int[16][48]);
void reverse_keys(int[16][48]);

void des_block(int*, int[16][48], int*);

#endif