#include <inttypes.h>
#include <stdlib.h>
#include <string.h>
#include "keccak.h"

/* Useful macros */
/* Rotate a 64b word to the left by n positions */
#define ROL64(a, n) ((((n)%64) != 0) ? ((((uint64_t)a) << ((n)%64)) ^ (((uint64_t)a) >> (64-((n)%64)))) : a)

/* Function prototypes */
unsigned char rc(unsigned int t);

/* Perform the KECCAK-p*[b, n_r] algorithm
 *
 * S  - the input bit string
 * b  - the length of the input string in bits
 * nr - the number of rounds
 * l  - the value of l associated with b (log2(b/25))
 *
 * Returns a pointer to the output bit string
 */
unsigned char *keccak_p_star(unsigned char *S, unsigned long b, int nr, int l)
{
    /* Implement this function using the code you wrote for Assignment 1.
     * You will need to implement one extra function, the permutation
     * pi^(-1) (the inverse of pi) described in Section 2.1 of the Ketje
     * document and Section 8 of the Assignment 2 instructions.
     */

    uint64_t *a;
    a = S;

    // 12+2l–nr to 12+2l-1 ... l = 6 and nr = 24
    for (int ir = (12+(2*l))-nr ; ir < (12+(2*l)) ; ir++)
    {
        pi_inv(a);
        theta(a);
        rho(a);
        pi(a);
        chi(a);
        iota(a,ir);
        pi(a);
    }
    return S;
}

/* Copy n bits from a buffer to another.
 *
 * dst   - the destination buffer, allocated by the caller
 * dst_o - the bit offset in the destination buffer
 * src   - the source buffer, allocated by the caller
 * src_o - the bit offset in the source buffer
 * n     - the number of bits to copy
 *
 * n does not need to be a multiple of 8.
 * dst and src must be at least ceiling(n/8) bytes long.
 */
void cpynbits(unsigned char *dst, unsigned int dst_o,
          const unsigned char *src, unsigned int src_o, unsigned int n)
{
    unsigned int v;
    unsigned int s_bit_cursor, s_byte_cursor, d_bit_cursor, d_byte_cursor;
    // Initialise cursors
    s_byte_cursor = src_o / 8;
    s_bit_cursor = src_o % 8;
    d_byte_cursor = dst_o / 8;
    d_bit_cursor = dst_o % 8;

    // If both cursors are byte-aligned, and n is a multiple of 8 bits
    if (s_bit_cursor == 0 && d_bit_cursor == 0 && n % 8 == 0) {
        // Just copy n/8 bytes byte by byte from src to dst
        for (unsigned int i = 0; i < n / 8; i++) {
            dst[d_byte_cursor + i] = src[s_byte_cursor + i];
        }
    } else {
        // Copy n bits bit by bit from src to dst
        for (unsigned long i = 0; i < n; i++) {
            // Get the bit
            v = ((src[s_byte_cursor] >> s_bit_cursor) & 1);
            // Set the bit
            dst[d_byte_cursor] ^=
                (-v ^ dst[d_byte_cursor]) & (1 << d_bit_cursor);
            // Increment cursors
            if (++s_bit_cursor == 8) {
                s_byte_cursor++;
                s_bit_cursor = 0;
            }
            if (++d_bit_cursor == 8) {
                d_byte_cursor++;
                d_bit_cursor = 0;
            }
        }
    }
}

/* Concatenate two bit strings (X||Y)
 *
 * Z     - the output bit string. The array is allocated by this function: the
 *         caller must take care of freeing it after use.
 * X     - the first bit string
 * X_len - the length of the first string in bits
 * Y     - the second bit string
 * Y_len - the length of the second string in bits
 *
 * Returns the length of the output string in bits. The length in Bytes of the
 * output C array is ceiling(output_bit_len/8).
 */
unsigned long concatenate(unsigned char **Z, const unsigned char *X,
              unsigned long X_len, const unsigned char *Y,
              unsigned long Y_len)
{
    /* The bit length of Z: the sum of X_len and Y_len */
    unsigned long Z_bit_len = X_len + Y_len;
    /* The byte length of Z:
     * the least multiple of 8 greater than X_len + Y_len */
    unsigned long Z_byte_len = (Z_bit_len / 8) + (Z_bit_len % 8 ? 1 : 0);
    // Allocate the output string and initialize it to 0
    *Z = calloc(Z_byte_len, sizeof(unsigned char));
    if (*Z == NULL)
        return 0;
    // Copy X_len bits from X to Z
    cpynbits(*Z, 0, X, 0, X_len);
    // Copy Y_len bits from Y to Z
    cpynbits(*Z, X_len, Y, 0, Y_len);

    return Z_bit_len;
}

/* Concatenate the 00, 01, 10, or 11 bit string to a given bit string
 * e.g. (X||00), (X||01), (X||10), (X||11)
 * Due to the KECCAK bit string representation, the bit strings are represented
 * as bytes respectively as:
 *       00 -> 0x00
 *       01 -> 0x02
 *       10 -> 0x01
 *       11 -> 0x03
 *
 * Z     - the output bit string. The array is allocated by this function: the
 *         caller must take care of freeing it after use.
 * X     - the bit string
 * X_len - the length of the string in bits
 *
 * Returns the length of the output string in bits. The length in Bytes of the
 * output C array is ceiling(output_bit_len/8).
 */
unsigned long concatenate_00(unsigned char **Z, const unsigned char *X,
                 unsigned long X_len)
{
    unsigned char zeroes[] = { 0x00 };
    return concatenate(Z, X, X_len, zeroes, 2);
}

unsigned long concatenate_01(unsigned char **Z, const unsigned char *X,
                 unsigned long X_len)
{
    unsigned char zeroone[] = { 0x02 };
    return concatenate(Z, X, X_len, zeroone, 2);
}

unsigned long concatenate_10(unsigned char **Z, const unsigned char *X,
                 unsigned long X_len)
{
    unsigned char onezero[] = { 0x01 };
    return concatenate(Z, X, X_len, onezero, 2);
}

unsigned long concatenate_11(unsigned char **Z, const unsigned char *X,
                 unsigned long X_len)
{
    unsigned char ones[] = { 0x03 };
    return concatenate(Z, X, X_len, ones, 2);
}

/* Performs the pad10*1(x, m) algorithm
 *
 * P - the output bit string. The array is allocated by this function: the
 *     caller must take care of freeing it after use.
 * x - the alignment value
 * m - the existing string length in bits
 *
 * Returns the length in bits of the output bit string.
 */
unsigned long pad10x1(unsigned char **P, unsigned int x, unsigned int m)
{
    /* 1. j = (-m-2) mod x */
    long j = (2 * x - 2 - (m % x)) % x;
    /* 2. P = 1 || zeroes(j) || 1 */
    // Compute P bit and byte length
    unsigned long P_bit_len = 2 + j;
    unsigned long P_byte_len = (P_bit_len / 8) + (P_bit_len % 8 ? 1 : 0);
    // Allocate P and initialize to 0
    *P = calloc(P_byte_len, sizeof(unsigned char));
    if (*P == NULL)
        return 0;
    // Set the 1st bit of P to 1
    (*P)[0] |= 1;
    // Set the last bit of P to 1
    (*P)[P_byte_len - 1] |= (1 << (P_bit_len - 1) % 8);

    return P_bit_len;
}

/* Perform the rc(t) algorithm
 *
 * t - the number of rounds to perform in the LFSR
 *
 * Returns a single bit stored as the LSB of an unsigned char.
 */
unsigned char rc(unsigned int t)
{
    unsigned int tmod = t % 255;
    /* 1. If t mod255 = 0, return 1 */
    if (tmod == 0)
        return 1;
    /* 2. Let R = 10000000
     *    The LSB is on the right: R[0] = R &0x80, R[8] = R &1 */
    unsigned char R = 0x80, R0;
    /* 3. For i from 1 to t mod 255 */
    for (unsigned int i = 1; i <= tmod; i++) {
        /* a. R = 0 || R */
        R0 = 0;
        /* b. R[0] ^= R[8] */
        R0 ^= (R & 1);
        /* c. R[4] ^= R[8] */
        R ^= (R & 0x1) << 4;
        /* d. R[5] ^= R[8] */
        R ^= (R & 0x1) << 3;
        /* e. R[6] ^= R[8] */
        R ^= (R & 0x1) << 2;
        /* Shift right by one */
        R >>= 1;
        /* Copy the value of R0 in */
        R ^= R0 << 7;
    }
    /* 4. Return R[0] */
    return R >> 7;
}

#define index(x,y) ((( 5 * (y % 5))+ (x % 5)))

uint64_t RC[24] = {0x0000000000000001,0x0000000000008082,0x800000000000808A,0x8000000080008000,0x000000000000808B,0x0000000080000001,0x8000000080008081,0x8000000000008009,0x000000000000008A,0x0000000000000088,0x0000000080008009,0x000000008000000A,0x000000008000808B,0x800000000000008B,0x8000000000008089,0x8000000000008003,0x8000000000008002,0x8000000000000080,0x000000000000800A,0x800000008000000A,0x8000000080008081,0x8000000000008080,0x0000000080000001,0x8000000080008008};

/* Perform the theta(A) algorithm
 * a - input state array
 */
void theta( uint64_t *a )
{
    uint64_t c[5] , d[5];

    // Allocate XOR of every y to c
    for ( unsigned int i = 0 ; i < 5 ; i++)
    {
        c[i] =  *(a+index(i,0)) ^ *(a+index(i,1)) ^ *(a+index(i,2)) ^ *(a+index(i,3)) ^ *(a+index(i,4));
    }

    // XOR Previous and next row rotated by 1 bit to D
    for ( unsigned int i = 0 ; i < 5 ; i++)
    {
        d[i] = c[((i-1)+5)%5] ^ ROL64(c[(i+1)%5],1);
    }

    // XOR every x to the original string
    for ( unsigned int i = 0 ; i < 5 ; i++)
    {   
        for ( unsigned int j = 0 ; j < 5 ; j++)
        {
            *(a + index(i,j)) = *(a + index(i,j)) ^ d[i];
        }
    }
}

/* Perform the p(A) algorithm
 * a - input state array
 */
void rho( uint64_t *a )
{    
    /* For t from 0 to 23:
     *   a. for all z such that 0≤z<w, let A′[x, y, z] = A[x, y, (z–(t+1)(t+2)/2) mod w];
     *   b. let (x, y) = (y, (2x+3y) mod 5).
     */
    int i = 1;
    int j = 0;
    int tmp = 0;
    for ( int t = 0; t < 24 ; t++)
    {
        *(a + index(i,j)) = ROL64(*(a + index(i,j)),((t+1)*(t+2))/2);
        tmp = i;
        i = j;
        j = ((2 * tmp) + (3 * j)) % 5;
    }
}

/* Perform the pi(A) algorithm
 * a - input state array
 */
void pi( uint64_t *a )
{
    uint64_t *b;
    b = calloc(25,sizeof(uint64_t));

    // For all x,y,z -> A′[x, y, z]= A[(x + 3y) mod 5, x, z].
    for (int i = 0 ; i < 5 ; i++)
    {
        for(int j = 0 ; j < 5 ; j++)
        {
            *(b + index(i,j)) = *(a + index((i+(3*j))%5,i));
        }
    }
    memcpy(a,b,200);
    free(b);
}

/* Perform the chi(A) algorithm
 * a - input state array
 */
void chi( uint64_t *a)
{
    uint64_t *b;
    uint64_t tmp;
    b = calloc(25,sizeof(uint64_t));

    // For all x,y,z -> A′[x,y,z] = A[x,y,z] ⊕ ((A[(x+1) mod 5, y, z] ⊕ 1) ⋅ A[(x+2) mod 5, y, z]).
    for (int i = 0 ; i < 5 ; i++)
    {
        for(int j = 0 ; j < 5 ; j++)
        {
            /* XOR with 0xFFFFFFFFFFFFFFFF to give the maximum value for uint64_t
             * Multiplication is the & operator
             */
            tmp = (*(a + index((i+1)%5,j)) ^ 0xFFFFFFFFFFFFFFFF) & (*(a + index((i+2)%5,j)));
            *(b + index(i,j)) = *(a + index(i,j)) ^ tmp;
        }
    }
    memcpy(a,b,200);
    free(b);
}

/* Perform the iota(A,ir) algorithm
 * a - input/output state array
 * ir - round index
 */
void iota( uint64_t *a , unsigned long ir)
{
    // a[0,0,z]=a[0,0,z] ⊕ RC[ir].
    *( a + index(0,0))= *( a + index(0,0))^ RC[ir];
}

/* Perform the pi_inv(A) algorithm
 * a - input state array
 */
void pi_inv( uint64_t *a )
{
    uint64_t *b;
    b = calloc(25,sizeof(uint64_t));

    // For all x,y,z -> A′[x, y, z]= A[y,(2x + 3y) mod 5, z].
    for (int i = 0 ; i < 5 ; i++)
    {
        for(int j = 0 ; j < 5 ; j++)
        {
            *(b + index(i,j)) = *(a + index(j,((2*i)+(3*j))%5));
        }
    }
    memcpy(a,b,200);
    free(b);
}
