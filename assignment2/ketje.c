#include <inttypes.h>
#include <stdlib.h>
#include <string.h>
#include "ketje.h"
#include "keccak.h"

/* Useful macros */
// Convert a bit length in the corresponding byte length, rounding up.
#define BYTE_LEN(x) ((x/8)+(x%8?1:0))


void keypack(unsigned char *packed,const unsigned char *key,int k_len,int length)
{
    printf("Key length %d\n", k_len+8);
    // Concatenate length
    *packed = (unsigned char) length / 8;
    
    memcpy((packed + 1),key,k_len/8);

    *(packed + (k_len+8)/8) = (char) 0x01;
}

void monkeyduplex(int r,int nstart,int nstep,int nstride)
{

}

void md_start(unsigned char *s,unsigned char *I,int i_len)
{
    memcpy(s,I,i_len);
    *(s + i_len) = (char) 0x01;
    *(s + 199) = (char) 0x80;         // Verify padding rules
    s = keccak_p_star(s,1600, 12, 8);
}

// Step and stride
void md_ss(unsigned char *s,unsigned char *sigma,int sigma_len,int l,int nr)
{
    unsigned char *P;
    P = calloc(200, sizeof(unsigned char));
    if (P == NULL)
        return;
        
    for ( int i = 0 ; i < 200 ; i++)
    {
        *(s + i) = *(s + i) ^ *(P + i);
    }

    s = keccak_p_star(s,1600, nr, 8);

    for ( int i = l ; i < 200 ; i++)
    {
        *(s + i) = 0;
    }
      
    free(P); 
}

void monkeywrap(int ρ,int nstart,int nstep,int nstride)
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
    packed = calloc((k_len+16+n_len)/8, sizeof(unsigned char));
    if (packed == NULL)
        return;

    keypack(packed,key,k_len,k_len+16);

    for (unsigned int i = 0 ; i < (k_len+16)/8 ; i++)
        printf("0x%02x ", *(packed + i));
    printf("\n");

    concatenate(&packed,packed, k_len+16 ,nonce, n_len);

    unsigned char *s;
    s = calloc(200, sizeof(unsigned char));
    if (s == NULL)
        return;

    md_start(s,packed,(k_len+16+n_len)/8);

    for (unsigned int i = 0 ; i < 200 ; i++)
        printf("0x%02x ", *(s + i));
    printf("\n");


    free(packed);
    free(s);

    return;
}
