#ifndef HEADER_PPK_H
#define HEADER_PPK_H

#include <stdint.h>
#include <openssl/evp.h>
#include <openssl/pem.h>

typedef EVP_PKEY PPK_KEY;

/* This function should be called before a call to any function in this unit. */
int init_ppk(void);

/* This function should be called to finish this unit once initialized. */
static inline void end_ppk(void) { /* Empty */ }

/* Generate a key pair. */
PPK_KEY *gen_keys(void);

/* Free key structure. */
static inline void ppk_free_key(PPK_KEY *pkey)
{
	EVP_PKEY_free(pkey);
}

/*
 * Obtain keys in DER (Distinguished Encoding Rules) format.
 */

/* Return the size of the private key in DER format. */
static inline int der_prvkey_size(PPK_KEY *pkey)
{
	return i2d_PrivateKey(pkey, NULL);
}

/* Return the size of the public key in DER format. */
static inline int der_pubkey_size(PPK_KEY *pkey)
{
	return i2d_PublicKey(pkey, NULL);
}

/* XXXder_of_pkey - Fill @buf with the private/public key.
 * @plen must hold the size of the buffer, and will receive the number of
 *	written bytes on success.
 * RETURN
 *	Return zero on success, and a negative number on failure.
 */
int prvder_of_pkey(PPK_KEY *pkey, uint8_t *buf, int *plen);
int pubder_of_pkey(PPK_KEY *pkey, uint8_t *buf, int *plen);

#define PPK_HASH_SIZE 20

/* Obtain the hash of private key.
 * @plen must hold the size of the buffer, and will receive the number of
 *	written bytes on success.
 * @hash should be at least PPK_HASH_SIZE bytes.
 */
int hash_of_key(PPK_KEY *pkey, uint8_t *hash, int *plen);

/* check_pkey - Test if @pkey hold a valid private and public keys.
 * It always fails if @pkey only holds a public key.
 * RETURN
 *	Zero on success; a negative number otherwise.
 */
int check_pkey(PPK_KEY *pkey);

/* Load pkey from a buffer that has a private key in DER format.
 * Keys are ckecked. Return NULL if it fails.
 */
PPK_KEY *pkey_of_prvder(const uint8_t *buf, int len);

/* Load pkey from a buffer that has a public key in DER format.
 * Return NULL if it fails.
 */
static inline PPK_KEY *pkey_of_pubder(const uint8_t *buf, int len)
{
	return d2i_PublicKey(EVP_PKEY_RSA, NULL, &buf, len);
}

/* Load pkey from a buffer that has a private key in
 * PEM (Privacy Enhanced Mail) format.
 * Keys are ckecked. Return NULL if it fails.
 */
PPK_KEY *pkey_of_prvpem(const uint8_t *buf, int len);

/* Load pkey from a buffer that has a public key in PEM.
 * Return NULL if it fails.
 */
PPK_KEY *pkey_of_pubpem(const uint8_t *buf, int len);

/* Write a private key in a file using PEM format.
 * Return zero on success, and a negative number on failure.
 */
static inline int write_prvpem(PPK_KEY *pkey, FILE *fp)
{
	return PEM_write_PrivateKey(fp, pkey, NULL, NULL, 0, NULL, NULL) <= 0 ?
		-1 : 0;
}

/* Write a public key in a file using PEM format.
 * Return zero on success, and a negative number on failure.
 */
static inline int write_pubpem(PPK_KEY *pkey, FILE *fp)
{
	return PEM_write_PUBKEY(fp, pkey) <= 0 ? -1 : 0;
}

/* Return the minimum size in bytes of the result buffer that must be
 * passed to functions encrypt or decrypt.
 * The returned value is the modulus size in bytes of the keys.
 */
int result_buffer_size(PPK_KEY *pkey);

/* Encrypt/decrupt @buf into @rbuf.
 * @rlen must have at least result_buffer_size(pkey) bytes.
 * RETURN
 *	Return zero on success, and a negative number on failure.
 * NOTE
 *	These functions work on single block, that is, @len must be at most
 *	result_buffer_size(pkey) - 41 bytes.
 *	If a longer block is necessary, consider increase the size of the keys.
 *	If multiple blocks are necessary, consider using a symmetric cypher
 *	whose key is exchanged/protected through public/private keys.
 */
int encrypt_blk(PPK_KEY *pkey, int use_prvkey, const uint8_t *buf, int len,
	uint8_t *rbuf, int *rlen);
int decrypt_blk(PPK_KEY *pkey, int use_prvkey, const uint8_t *buf, int len,
	uint8_t *rbuf, int *rlen);

#endif /* HEADER_PPK_H */
