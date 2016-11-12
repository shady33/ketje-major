#include <inttypes.h>
#include <stdlib.h>
#include <string.h>
#include "stdio.h"
#include "ketje.h"
#include "keccak.h"

/* Useful macros */
// Convert a bit length in the corresponding byte length, rounding up.
#define BYTE_LEN(x) ((x/8)+(x%8?1:0))

/* Keypack function
 * key - encryption key
 * k_len - lenght of encryption key
 * length - total length of packed key
 * packed - output packed key
 */
void keypack(unsigned char *packed,const unsigned char *key,int k_len,int length)
{
    // Set first byte to byte length for packed
    *packed = length / 8;
    
    // Copy key into packed    
    memcpy((packed + 1),key,k_len/8);

    // Simple padding i.e. set byte after copied string to 0x01
    *(packed + (k_len+8)/8) = (char) 0x01;
}

/* MonekyDuplex Start
 * I - Input string
 * i_len - lenght of input string
 * s - output state array
 */
void md_start(unsigned char *s,unsigned char *I,int i_len)
{
    unsigned char *inter;
    unsigned char *inter_2;

    unsigned int d = pad10x1(&inter,1600,i_len);

    concatenate(&inter_2, I, i_len, inter, d);

    inter_2 = keccak_p_star(inter_2,1600, 12, 6);

    memcpy(s,inter_2,200);

    free(inter);
    free(inter_2);
}

/* MonekyDuplex Step and Stride functions combined
 * I - Input string
 * i_len - lenght of input string
 * s - output state array
 */
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

/* MonekyWrap Initialize
 * key - encryption key
 * k_len - lenght of encryption key
 * s - output state array
 */
void mw_init(unsigned char *s,const unsigned char *key,int k_len,const unsigned char *nonce,int n_len)
{
    unsigned char *packed;
    unsigned char *packed_nonce;

    packed = calloc((k_len+16)/8, sizeof(unsigned char));
    if (packed == NULL)
        return;

    // keypack(K, |K| + 16)
    keypack(packed,key,k_len,k_len+16);

    // keypack(K, |K| + 16) || N
    concatenate(&packed_nonce,packed, k_len+16 ,nonce, n_len);

    // D.start(keypack(K, |K| + 16)||N) 2 2
    md_start(s,packed_nonce,k_len+16+n_len);

    free(packed);
    free(packed_nonce);
}

void mw_wrap(unsigned char *cryptogram,unsigned char *tag,int t_len,const unsigned char *A,int a_len, const unsigned char *B,int b_len,unsigned char *s)
{

    // for i = 0 to ∥A∥ − 2 do
    // D.step(Ai||00, 0)
    int a_div = a_len/256;
    int a_mod = a_len%256;
    int loop_iter = 0;
    if (a_mod == 0 )
    {
        a_div = a_div - 1;
    }

    if(a_div > 0)
    {
        loop_iter = a_div;
    }else{
        a_div = 0;
    }

    unsigned char *a_loop;
    if (a_len > 256)
        concatenate_00(&a_loop,A,256);
    else
        concatenate_00(&a_loop,A,a_len);

    // Check inside loop
    for(int i = 0 ; i < loop_iter ; i++ )
    {
        md_ss(NULL,s,a_loop,258,0,1);
        memcpy(a_loop,(A + ((i*256)/8)),32);
    }
   
    unsigned char *inter;
    // A∥A∥−1||01
    unsigned long d;

    if ( a_len == 0)
    {
        d = concatenate_01(&inter, NULL ,0);
    }
    else if(a_mod == 0)
    {
        d = concatenate_01(&inter, (A + ((a_div*256)/8)) ,256);
    }
    else
    {
        d = concatenate_01(&inter, (A + ((a_div*256)/8)) ,a_len%256);
    }

    // Len(B0)
    int b0 = b_len/256 ? 256 : b_len%256;

    unsigned char *Z;
    Z = calloc( b0/8, sizeof(unsigned char));
    if (Z == NULL)
        return;

    // Z = D.step(A∥A∥−1||01, |B0|)
    md_ss(Z,s,inter,d,b0,1);

    // C0 = B0 ⊕ Z
    for(int i = 0 ; i < b0/8 ; i++)
    {
        *(cryptogram + i) = *(B + i) ^ *(Z+i);
    }

    int b_div = b_len/256;
    int b_mod = b_len%256;
    loop_iter = 0;
    if (b_mod == 0 )
    {
        b_div = b_div - 1;
    }

    if(b_div > 0)
    {
        loop_iter = b_div;
    }else
    {
        b_div = 0;
    }

    unsigned char *b_loop;
    concatenate_11(&b_loop,B,b0);
    int b_i_1_len = 0;

    // for i = 0 to ∥B∥ − 2 do
    // Z = D.step(Bi||11, |Bi+1|)
    // Ci+1 = Bi+1 ⊕ Z
    for(int i = 0 ; i < loop_iter ; i++ )
    {
        if (i < (b_len / 256) - 1)
            b_i_1_len = 256;
        else
            b_i_1_len = b_len % 256;

        md_ss(Z,s,b_loop,258,b_i_1_len,1);

        int ith = ((i+1) * 256 ) / 8;
        
        for(int j = 0 ; j < BYTE_LEN(b_i_1_len); j++)
        {
            *(cryptogram + ith + j) = *(B + ith + j) ^ *(Z + j);
        }
        memcpy(b_loop,(B + ith),b_i_1_len/8);
    }

    unsigned char *b_inter_1;
    
    if ( b_len == 0)
    {
        d = concatenate_10(&b_inter_1, NULL ,0);
    }else if(b_mod == 0)
    {
        d = concatenate_10(&b_inter_1, (B + ((b_div*256)/8)) ,256);
    }
    else
    {
        d = concatenate_10(&b_inter_1, (B + ((b_div*256)/8)) ,b_len%256);
    }

    // T = D.stride(B∥B∥−1||10, ρ)
    md_ss(tag,s,b_inter_1,d,256,6);

    // While loop may not be needed

    // Freeing
    free(b_inter_1);
    free(b_loop);
    free(Z);
    free(inter);
    free(a_loop);
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

    /* Implement this function */

    // State array of 1600 bits
    unsigned char *s;
    s = calloc( 200, sizeof(unsigned char));
    if (s == NULL)
        return;

    // MonkeyWrap Initialize
    mw_init(s,key,k_len,nonce,n_len);

    // MonekyWrap
    mw_wrap(cryptogram,tag,t_len, header,h_len,data,d_len,s);

    free(s);
}
