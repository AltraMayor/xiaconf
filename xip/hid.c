#include <stdio.h>
#include <limits.h>
#include <string.h>
#include <assert.h>
#include <asm/byteorder.h>

#include "hid.h"
#include "ppk.h"

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

static char *split_buf(char *buf, int buflen)
{
	char *p = buf;
	int left = buflen;
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

int write_pub_hid_file(const char *infilename, FILE *outf)
{
	int rc = -1;
	FILE *f;
	char buf[8*1024];
	size_t buflen;
	char *prvpem;
	int prvpem_len;
	PPK_KEY *pkey;
	

	f = fopen(infilename, "r");
	if (!f)
		goto out;

	buflen = fread(buf, 1, sizeof(buf), f);
	assert(buflen < sizeof(buf));
	prvpem = split_buf(buf, buflen);
	if (!prvpem)
		goto close_f;

	prvpem_len = buflen - (prvpem - buf);
	pkey = pkey_of_prvpem(prvpem, prvpem_len);
	if (!pkey)
		goto close_f;
	
	fprintf(outf, "%s\n", buf);
	if (write_pubpem(pkey, outf))
		goto pkey;

	rc = 0;
pkey:
	ppk_free_key(pkey);
close_f:
	fclose(f);
out:
	return rc;
}
