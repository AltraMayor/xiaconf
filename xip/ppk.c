/*
 * Private/Public Key Infrastructure
 */

#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <openssl/rsa.h>
#include <openssl/bio.h>
#include <openssl/rand.h>

#include "ppk.h"

int init_ppk(void)
{
	if (RAND_load_file("/dev/random", 4) <= 0)
		if (RAND_load_file("/dev/urandom", 128) <= 0)
			return -1;
	return 0;
}

PPK_KEY *gen_keys(void)
{
	PPK_KEY *pkey;
	RSA *rsa;

	pkey = EVP_PKEY_new();
	if (!pkey)
		goto out;

	/* Generate a RSA key. */
	do {
		int rc;
		/* 2048-bit key. */
		rsa = RSA_generate_key(2048, RSA_F4, NULL, NULL);
		if (!rsa)
			goto pkey;
		rc = RSA_check_key(rsa);
		if (rc < 0) {
			goto rsa;
		} else if (!rc) {
			RSA_free(rsa);
			rsa = NULL;
		}
	} while (!rsa);
	if (RSA_blinding_on(rsa, NULL) <= 0)
		goto rsa;

	if (EVP_PKEY_assign_RSA(pkey, rsa) <= 0)
		goto rsa;
	return pkey;

rsa:
	RSA_free(rsa);
pkey:
	EVP_PKEY_free(pkey);
out:
	return NULL;
}

/* Internal function. Don't call it directly. */
static inline int __der_of_pkey(int (*i2d)(PPK_KEY *, uint8_t **),
	int der_len, PPK_KEY *pkey, uint8_t *buf, int *plen)
{
	uint8_t *next = buf;
	if (der_len <= 0)
		return -1;
	if (der_len > *plen)
		return -1;
	*plen = i2d(pkey, &next);
	assert(der_len == *plen);
	return 0;
}

int pubder_of_pkey(PPK_KEY *pkey, uint8_t *buf, int *plen)
{
	return __der_of_pkey(i2d_PublicKey, der_pubkey_size(pkey),
		pkey, buf, plen);
}

int prvder_of_pkey(PPK_KEY *pkey, uint8_t *buf, int *plen)
{
	return __der_of_pkey(i2d_PrivateKey, der_prvkey_size(pkey),
		pkey, buf, plen);
}

int hash_of_key(PPK_KEY *pkey, void *hash, int *plen)
{
	uint8_t *buf;
	int size1, size2;
	const EVP_MD *sha1;
	EVP_MD_CTX ctx;
	int rc = -1;

	/* Obtain public key in DER format. */
	size1 = size2 = der_pubkey_size(pkey);
	if (size1 <= 0)
		goto out;
	buf = malloc(size1);
	if (!buf)
		goto out;
	if (pubder_of_pkey(pkey, buf, &size2))
		goto buf;
	assert(size1 == size2);
	
	/* Obtain hash of public key. */
	sha1 = EVP_sha1();
	size1 = EVP_MD_size(sha1);
	if (size1 > *plen)
		goto buf;
	/* The following memset isn't well documented, but it's required before
	 * calling EVP_DigestInit_ex with a ctx that hasn't _ever_ been
	 * initialized.
	 */
	memset(&ctx, 0, sizeof(ctx));
	if (EVP_DigestInit_ex(&ctx, sha1, NULL) <= 0)
		goto buf;
	if (EVP_DigestUpdate(&ctx, buf, size1) <= 0)
		goto buf;
	if (EVP_DigestFinal_ex(&ctx, hash, plen) <= 0)
		goto buf;
	assert(*plen == size1);
	if (EVP_MD_CTX_cleanup(&ctx) <= 0)
		goto buf;
	rc = 0;

buf:
	free(buf);
out:
	return rc;
}

static inline int has_prvkey(RSA *rsa)
{
	return !!rsa->d;
}

int check_pkey(PPK_KEY *pkey)
{
	RSA *rsa;
	int rc;
	rsa = EVP_PKEY_get1_RSA(pkey);
	if (!rsa)
		return -1;
	/* Testing that rsa has a private key is very important because
	 * RSA_check_key blows up if it does not!
	 */
	if (!has_prvkey(rsa))
		return -1;
	rc = RSA_check_key(rsa);
	RSA_free(rsa);
	return rc <= 0 ? -1 : 0;
}

/* Internal function. Don't call it directly. */
static inline PPK_KEY *check_and_protect_pkey(PPK_KEY *pkey)
{
	RSA *rsa;
	if (!pkey)
		goto out;
	if (check_pkey(pkey))
		goto pkey;
	rsa = EVP_PKEY_get1_RSA(pkey);
	if (!rsa)
		goto pkey;
	if (RSA_blinding_on(rsa, NULL) <= 0)
		goto rsa;
	RSA_free(rsa);
	return pkey;

rsa:
	RSA_free(rsa);
pkey:
	EVP_PKEY_free(pkey);
out:
	return NULL;
}

PPK_KEY *pkey_of_prvder(const uint8_t *buf, int len)
{
	PPK_KEY *pkey = d2i_PrivateKey(EVP_PKEY_RSA, NULL, &buf, len);
	return check_and_protect_pkey(pkey);
}

PPK_KEY *pkey_of_prvpem(const uint8_t *buf, int len)
{
	BIO *bio;
	PPK_KEY *pkey;
	/* The cast below is needed only because OpenSSL does not
	 * add the qualifier const to the prototype of BIO_new_mem_buf.
	 */
	bio = BIO_new_mem_buf((void *)buf, len);
	if (!bio)
		return NULL;
	pkey = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
	BIO_vfree(bio);
	return check_and_protect_pkey(pkey);
}

PPK_KEY *pkey_of_pubpem(const uint8_t *buf, int len)
{
	BIO *bio;
	PPK_KEY *pkey;
	/* The cast below is needed only because OpenSSL does not
	 * add the qualifier const to the prototype of BIO_new_mem_buf.
	 */
	bio = BIO_new_mem_buf((void *)buf, len);
	if (!bio)
		return NULL;
	pkey = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
	BIO_vfree(bio);
	return pkey;
}

int result_buffer_size(PPK_KEY *pkey)
{
	int size;
	RSA *rsa = EVP_PKEY_get1_RSA(pkey);
	if (!rsa)
		return 0;
	size = RSA_size(rsa);
	RSA_free(rsa);
	return size;
}

/* Internal function. Don't call it directly. */
static inline int __crypt(int decrypt, int use_prvkey,
	PPK_KEY *pkey, const uint8_t *buf, int len, uint8_t *rbuf, int *rlen)
{
	RSA *rsa;
	int min_size;
	int (*do_it)(int, const uint8_t *, uint8_t *, RSA *, int);

	rsa = EVP_PKEY_get1_RSA(pkey);
	if (!rsa)
		goto out;
	min_size = RSA_size(rsa);
	if (*rlen < min_size)
		goto rsa;
	if (decrypt) {
		if (len != min_size)
			goto rsa;
		do_it = use_prvkey ? RSA_private_decrypt : RSA_public_decrypt;
	} else {
		/* See RSA_public_encrypt(3SSL) for the magic number. */
		if (len > min_size - 41)
			goto rsa;
		do_it = use_prvkey ? RSA_private_encrypt : RSA_public_encrypt;
	}
	*rlen = do_it(len, buf, rbuf, rsa, RSA_PKCS1_OAEP_PADDING);
	if (*rlen < 0)
		goto rsa;
	RSA_free(rsa);
	return 0;

rsa:
	RSA_free(rsa);
out:
	return -1;
}

int encrypt_blk(PPK_KEY *pkey, int use_prvkey, const uint8_t *buf, int len,
	uint8_t *rbuf, int *rlen)
{
	return __crypt(0, use_prvkey, pkey, buf, len, rbuf, rlen);
}

int decrypt_blk(PPK_KEY *pkey, int use_prvkey, const uint8_t *buf, int len,
	uint8_t *rbuf, int *rlen)
{
	return __crypt(1, use_prvkey, pkey, buf, len, rbuf, rlen);
}
