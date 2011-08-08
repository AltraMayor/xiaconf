#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <assert.h>
#include <unistd.h>

#include "ppk.h"

/*
 * Main
 */

void print_hex(unsigned char *buf, int len)
{
	int i;
	for (i = 0; i < len; i++)
		printf("%02x", buf[i]);
}

#define BUFSIZE 8192
#define PRVFILE "prv-key.pem"
#define PUBFILE "pub-key.pem"

int main(void)
{
	PPK_KEY *pkey;

	FILE *f;

	uint8_t buf[BUFSIZE];
	int buflen;
	PPK_KEY *prvkey, *pubkey;

	uint8_t *prvder, *pubder;
	int prvderlen, pubderlen;

	uint8_t hash[PPK_HASH_SIZE];
	int hashlen;

	uint8_t *rbuf;
	int rlen;

	/* Generate a key pair and show in PEM format. */
	pkey = gen_keys();
	assert(pkey);
	assert(!write_prvpem(pkey, stdout));
	assert(!write_pubpem(pkey, stdout));
	printf("\n");

	/* Save keys in PEM format. */
	f = fopen(PRVFILE, "w");
	assert(f);
	assert(!write_prvpem(pkey, f));
	assert(!fclose(f));
	f = fopen(PUBFILE, "w");
	assert(f);
	assert(!write_pubpem(pkey, f));
	assert(!fclose(f));
	printf("PEM files saved\n\n");

	/* Load key form PEM */
	f = fopen(PRVFILE, "r");
	assert(f);
	buflen = fread(buf, 1, BUFSIZE, f);
	assert(!pkey_of_pubpem(buf, buflen));
	prvkey = pkey_of_prvpem(buf, buflen);
	assert(prvkey);
	ppk_free_key(prvkey);
	prvkey = NULL;
	assert(!fclose(f));
	f = fopen(PUBFILE, "r");
	assert(f);
	buflen = fread(buf, 1, BUFSIZE, f);
	assert(!pkey_of_prvpem(buf, buflen));
	pubkey = pkey_of_pubpem(buf, buflen);
	assert(pubkey);
	ppk_free_key(pubkey);
	pubkey = NULL;
	assert(!fclose(f));
	printf("PEM files read\n\n");

	/* Obtain keys in DER. */
	prvderlen = der_prvkey_size(pkey);
	prvder = malloc(prvderlen);
	assert(prvder);
	assert(!prvder_of_pkey(pkey, prvder, &prvderlen));
	printf("Private DER: ");
	print_hex(prvder, prvderlen);
	printf("\n");

	pubderlen = der_pubkey_size(pkey);
	pubder = malloc(pubderlen);
	assert(pubder);
	assert(!pubder_of_pkey(pkey, pubder, &pubderlen));
	printf("Public DER: ");
	print_hex(pubder, pubderlen);
	printf("\n\n");

	/* Load keys from DER. */
	prvkey = pkey_of_prvder(prvder, prvderlen);
	assert(prvkey);
	pubkey = pkey_of_pubder(pubder, pubderlen);
	assert(pubkey);
	assert(!pkey_of_prvder(pubder, pubderlen));
	assert(!pkey_of_pubder(prvder, prvderlen));
	assert(check_pkey(pubkey));

	/* Obtain a DAG of the key pair. */
	hashlen = sizeof(hash);
	assert(!hash_of_key(pkey, hash, &hashlen));
	printf("hid-");
	print_hex(hash, hashlen);
	printf("-0\n\n");

	/* Encrypt/Decrypt. */
	strcpy(buf, "There is a secret!");
	buflen = strlen(buf) + 1;
	rlen = result_buffer_size(pkey);
	printf("Result buffer size = %i\n", rlen);
	rbuf = malloc(rlen);
	assert(!encrypt_blk(pkey, 0, buf, buflen, rbuf, &rlen));
	printf("Encrypted message: ");
	print_hex(rbuf, rlen);
	printf("\n");
	memset(buf, 0, buflen);
	buflen = result_buffer_size(pkey);
	assert(buflen <= BUFSIZE);
	assert(!decrypt_blk(pkey, 1, rbuf, rlen, buf, &buflen));
	printf("Decrypted message (length %i): %s\n\n", buflen - 1, buf);
	
	free(rbuf);
	ppk_free_key(pubkey);
	ppk_free_key(prvkey);
	free(pubder);
	free(prvder);
	ppk_free_key(pkey);

	assert(!unlink(PRVFILE));
	assert(!unlink(PUBFILE));
	return 0;
}
