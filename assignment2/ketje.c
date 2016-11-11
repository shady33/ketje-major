#include <inttypes.h>
#include <stdlib.h>
#include <string.h>
#include "stdio.h"
#include "ketje.h"
#include "keccak.h"

/* Useful macros */
// Convert a bit length in the corresponding byte length, rounding up.
#define BYTE_LEN(x) ((x/8)+(x%8?1:0))


void keypack(unsigned char *packed,const unsigned char *key,int k_len,int length)
{
    printf("Key length %d %x\n", k_len+16, length/8);
    // Concatenate length
    *packed = length / 8;
    
    memcpy((packed + 1),key,k_len/8);

    *(packed + (k_len+8)/8) = (char) 0x01;
}

void monkeyduplex(int r,int nstart,int nstep,int nstride)
{

}

void md_start(unsigned char *s,unsigned char *I,int i_len)
{
    unsigned char *inter;
    unsigned char *inter_2;

    unsigned int d = pad10x1(&inter,1600,i_len);

    unsigned long l = concatenate(&inter_2, I, i_len, inter, d);

    inter_2 = keccak_p_star(inter_2,1600, 12, 6);

    memcpy(s,inter_2,200);

    free(inter);
    free(inter_2);
}

// Step and stride
void md_ss(unsigned char *Z,unsigned char *s,unsigned char *sigma,int sigma_len,int l,int nr)
{
    unsigned char *P;
    unsigned char *inter;
    unsigned char *P1;

    unsigned int d = pad10x1(&inter,260,sigma_len);

    d = concatenate(&P, sigma, sigma_len, inter, d);

    unsigned char zeroes[] = { 0x00 };

    d = concatenate(&P1, P, d, zeroes, 4);

    for ( int i = 0 ; i < 33 ; i++ )
    {
        *(s + i) = *(s + i) ^ *(P1 + i);
    }

    s = keccak_p_star(s,1600, nr, 6);

    memcpy(Z,s,(l/8));

    free(inter);
    free(P); 
    free(P1);
}

void mw_wrap(unsigned char *cryptogram,unsigned char *tag,unsigned char *A,unsigned char *B,int l)
{

}

/* Perform the Ketje Major authenticated encryption operation on a message.
 *
 * cryptogram - the output buffer for the ciphertext, allocated by the caller.
 *              The buffer is the same size as the "data" plaintext buffer.
 * tag        - the output buffer for the tag, allocated by the caller.
 * t_len      - the requested tag length in bits.
 * key        - the key, provided by the caller.
 * k_len      - the key length in bits.
 * nonce      - the nonce, provided by the caller.
 * n_len      - the nonce length in bits.
 * data       - the plaintext, provided by the caller.
 * d_len      - the plaintext length in bits.
 * header     - the additional plaintext, provided by the caller.
 * h_len      - the additional plaintext length in bits.
 */
void ketje_mj_e(unsigned char *cryptogram,
        unsigned char *tag, unsigned int t_len,
        const unsigned char *key, unsigned int k_len,
        const unsigned char *nonce, unsigned int n_len,
        const unsigned char *data, unsigned long d_len,
        const unsigned char *header, unsigned long h_len)
{
    /* Ketje Major-specific parameters:
     *   f        = KECCAK-p*[1600]
     *   rho      = 256
     * For all Ketje instances:
     *   n_start  = 12
     *   n_step   = 1
     *   n_stride = 6
     */
    // Assuming b = 1600 bits -- Verify 

    /* Implement this function */
    // monkeywrap(256,12,1,6);

    unsigned char *packed;
    unsigned char *packed_nonce;

    packed = calloc((k_len+16)/8, sizeof(unsigned char));
    if (packed == NULL)
        return;

    // keypack(K, |K| + 16)
    keypack(packed,key,k_len,k_len+16);

    // keypack(K, |K| + 16) || N
    concatenate(&packed_nonce,packed, k_len+16 ,nonce, n_len);
    
    unsigned char *s;
    s = calloc( 200, sizeof(unsigned char));
    if (s == NULL)
        return;

    // D.start(keypack(K, |K| + 16)||N) 2 2
    md_start(s,packed_nonce,k_len+16+n_len);

    // for i = 0 to ∥A∥ − 2 do
    // D.step(Ai||00, 0)

    int loop_iter = ((h_len/256) - 2);
    if (loop_iter < 0)
        loop_iter = 0;

    // Check inside loop concatenate nonesnse left
    for(unsigned int i = 0 ; i < loop_iter ; i++ )
    {
       md_ss(NULL,s,*(header + (i*256)/8),264,0,1);
    }

    unsigned char *inter;
    // A∥A∥−1||01
    unsigned long d = concatenate_01(&inter, (header + (h_len/256) - 1),h_len%256);

    // Len(B0)
    int b0 = d_len/256 ? 256 : d_len%256;

    unsigned char *Z;
    Z = calloc( b0/8, sizeof(unsigned char));
    if (Z == NULL)
        return;

    // Z = D.step(A∥A∥−1||01, |B0|)
    md_ss(Z,s,inter,d,b0,1);

    printf("Printing after thing\n");
    for(int i = 0 ; i < 200 ; i++)
        printf("%02x ", *(s+i));
    printf("\n");

    // C0 = B0 ⊕ Z
    for(int i = 0 ; i < b0/8 ; i++)
        *(cryptogram + i) = *(data + i) ^ *(Z+i);

    loop_iter = ((d_len/256) - 2);

    if (loop_iter < 0)
        loop_iter = 0;

    // for i = 0 to ∥B∥ − 2 do
    // Z = D.step(Bi||11, |Bi+1|)
    // Ci+1 = Bi+1 ⊕ Z    
    for(unsigned int i = 0 ; i < loop_iter ; i++ )
    {
       md_ss(NULL,s,*(header + (i*256)/8),264,0,1);
    }
    
    unsigned char *b_inter_1;
    d = concatenate_10(&b_inter_1, (data + ((d_len/256) - (d_len%256?0:1))) ,d_len%256);

    // T = D.stride(B∥B∥−1||10, ρ)
    md_ss(tag,s,b_inter_1,d,256,6);

    // While loop may not be needed
    printf("Tag:\n");
    for(int i = 0 ; i < t_len/8 ; i++)
        printf("0x%02x " , *(tag + i));
    printf("\n");

    free(packed);
    free(s);

    return;
}
