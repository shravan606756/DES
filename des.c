#include "des.h"
#include "tables.h"

void sbox_sub(int *in,int *out)
{
    int k=0;
    for(int i=0;i<8;i++)
    {
        int r=in[i*6]*2+in[i*6+5];
        int c=in[i*6+1]*8+in[i*6+2]*4+in[i*6+3]*2+in[i*6+4];
        int v=sbox[i][r][c];

        for(int j=3;j>=0;j--) out[k++]=(v>>j)&1;
    }
}

void generate_keys(int *key,int keys[16][48])
{
    int t[56],C[28],D[28];

    permute(key,t,PC1,56);

    for(int i=0;i<28;i++) C[i]=t[i],D[i]=t[i+28];

    for(int i=0;i<16;i++)
    {
        shift_left(C,shift_table[i]);
        shift_left(D,shift_table[i]);

        int CD[56];
        for(int j=0;j<28;j++) CD[j]=C[j],CD[j+28]=D[j];

        permute(CD,keys[i],PC2,48);
    }
}

void des_block(int *pt,int keys[16][48],int *ct)
{
    int ip[64];
    permute(pt,ip,IP,64);

    int L[32],R[32];
    for(int i=0;i<32;i++) L[i]=ip[i],R[i]=ip[i+32];

    for(int i=0;i<16;i++)
    {
        int e[48],x[48],s[32],f[32],nr[32];

        permute(R,e,E,48);
        xor(e,keys[i],x,48);
        sbox_sub(x,s);
        permute(s,f,P,32);

        xor(L,f,nr,32);

        for(int j=0;j<32;j++) L[j]=R[j],R[j]=nr[j];
    }

    int RL[64];
    for(int i=0;i<32;i++) RL[i]=R[i],RL[i+32]=L[i];

    permute(RL,ct,FP,64);
}