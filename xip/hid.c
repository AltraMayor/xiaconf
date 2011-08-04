#include <stdio.h>
#include <limits.h>
#include <string.h>
#include <assert.h>
#include <asm/byteorder.h>

#include "hid.h"

#ifndef HID_PRV_PATH
#define HID_PRV_PATH "/etc/xia/hid/prv/"
#endif

void get_ffn(char *ffn, const char *filename)
{
	if (strchr(filename, '/')) {
		strncpy(ffn, filename, PATH_MAX);
		ffn[PATH_MAX - 1] = '\0';
	} else {
		int left = PATH_MAX - strlen(HID_PRV_PATH) - 1;
		strcpy(ffn, HID_PRV_PATH);
		strncat(ffn, filename, left);
	}
}

int write_new_hid_file(const char *filename)
{
	int rc = -1;
	FILE *f;
	PPK_KEY *pkey;
	__be32 hash[5];
	int hashlen;

	f = fopen(filename, "w");
	if (!f)
		goto out;
	pkey = gen_keys();
	if (!pkey)
		goto close_f;
	
	/* Obtain a DAG of the key pair. */
	hashlen = sizeof(hash);
	if (hash_of_key(pkey, hash, &hashlen))
		goto pkey;
	fprintf(f, "hid-%08x%08x%08x%08x%08x-0\n\n",
		__be32_to_cpu(hash[0]), __be32_to_cpu(hash[1]),
		__be32_to_cpu(hash[2]), __be32_to_cpu(hash[3]),
		__be32_to_cpu(hash[4]));

	if (write_prvpem(pkey, f))
		goto pkey;

	rc = 0;
pkey:
	ppk_free_key(pkey);
close_f:
	fclose(f);
out:
	return rc;
}

static char *split_buf(char *buf, int len)
{
	char *p = buf;
	int left = len;
	int empty = 1;

	while (left > 0) {
		if (*p == '\n') {
			if (empty) {
				*p = '\0';
				return (p + 1);
			} else {
				empty = 1;
			}
		} else
			empty = 0;
		p++; left--;
	}

	return NULL;
}

static int read_and_split_buf(const char *filename, char *buf, int *plen,
	char **psecond_half, int *second_half_len)
{
	int rc = -1;
	FILE *f;
	int bufsize = *plen;
	int len;
	char *sec_half;

	f = fopen(filename, "r");
	if (!f)
		goto out;

	len = fread(buf, 1, bufsize, f);
	assert(len < bufsize);
	sec_half = split_buf(buf, len);
	if (!sec_half)
		goto close_f;

	*plen = len;
	*psecond_half = sec_half;
	*second_half_len = len - (sec_half - buf);
	rc = 0;

close_f:
	fclose(f);
out:
	return rc;
}

#define HID_FILE_BUFFER_SIZE (8*1024)

int write_pub_hid_file(const char *infilename, FILE *outf)
{
	int rc = -1;
	char buf[HID_FILE_BUFFER_SIZE];
	int buflen;
	char *prvpem;
	int prvpem_len;
	PPK_KEY *pkey;
	
	buflen = sizeof(buf);
	if (read_and_split_buf(infilename, buf, &buflen, &prvpem, &prvpem_len))
		goto out;

	pkey = pkey_of_prvpem(prvpem, prvpem_len);
	if (!pkey)
		goto out;
	
	fprintf(outf, "%s\n", buf);
	if (write_pubpem(pkey, outf))
		goto pkey;

	rc = 0;
pkey:
	ppk_free_key(pkey);
out:
	return rc;
}

int read_hid_file(const char *filename, int is_prv, struct xia_addr *addr,
			PPK_KEY **ppkey)
{
	int rc = -1;
	char buf[HID_FILE_BUFFER_SIZE];
	int buflen;
	char *pem;
	int pem_len;

	buflen = sizeof(buf);
	if (read_and_split_buf(filename, buf, &buflen, &pem, &pem_len))
		goto out;

	if (xia_pton(buf, INT_MAX, addr, 0, NULL) <= 0)
		goto out;

	*ppkey = is_prv ?	pkey_of_prvpem(pem, pem_len):
				pkey_of_pubpem(pem, pem_len);
	if (!*ppkey)
		goto out;

	rc = 0;

out:
	return rc;
}
