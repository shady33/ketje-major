#ifndef KETJE_H
#define KETJE_H

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
		const unsigned char *header, unsigned long h_len);

/* You can add your own functions below this line.
 * Do NOT modify anything above. */
void md_start(unsigned char *s,unsigned char *I,int i_len);

void md_ss(unsigned char *Z,unsigned char *s,unsigned char *sigma,int sigma_len,int l,int nr);

void keypack(unsigned char *packed,const unsigned char *key,int key_len,int lenght);

void mw_init(unsigned char *s,const unsigned char *key,int k_len,const unsigned char *nonce,int n_len);

void mw_wrap(unsigned char *cryptogram,unsigned char *tag,int t_len,const unsigned char *A,int a_len,const unsigned char *B,int b_len,unsigned char *s);

#endif				/* KETJE_H */
