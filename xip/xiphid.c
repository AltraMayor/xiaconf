#include <stdio.h>
#include <limits.h>
#include <string.h>
#include <assert.h>
#include <asm/byteorder.h>
#include <net/xia.h>

#include "xip_common.h"
#include "ppk.h"
#include "utils.h"
#include "ppal_map.h"
#include "dag.h"
#include "ll_map.h"

#ifndef HID_PRV_PATH
#define HID_PRV_PATH "/etc/xia/hid/prv/"
#endif

static int usage(void)
{
	fprintf(stderr,
"Usage: xip hid { new | getpub } PRVFILENAME\n"
"       xip hid addaddr PRVFILENAME dev STRING\n");
	return -1;
}

/* get_ffn - obtains Final FileName.
 *
 * @ffn must be at least PATH_MAX (available in <limits.h>).
 *
 * If @filename includes a '/', it assumes to be a filename with full path,
 * otherwise it assumes it is to be stored in the default configuration path.
 */
static void get_ffn(char *ffn, const char *filename)
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

/* write_new_hid_file - generates a new HID and save to @filename.
 *
 * RETURN
 *	returns zero on success; otherwise a negative number.
 */
static int write_new_hid_file(const char *filename)
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

static int do_newhid(int argc, char **argv)
{
	char ffn[PATH_MAX];

	if (argc != 1) {
		fprintf(stderr, "Wrong number of parameters\n");
		return usage();
	}
	
	get_ffn(ffn, argv[0]);
	if (write_new_hid_file(ffn)) {
		fprintf(stderr, "Couldn't create new HID file\n");
		return -1;
	}

	return 0;
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

/* write_pub_hid_file - reads @infilename, a file with the private key, and
 * writes @outf a file with the public key.
 *
 * RETURN
 *	returns zero on success; otherwise a negative number.
 */
static int write_pub_hid_file(const char *infilename, FILE *outf)
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

static int do_getpub(int argc, char **argv)
{
	char ffn[PATH_MAX];

	if (argc != 1) {
		fprintf(stderr, "Wrong number of parameters\n");
		return usage();
	}
	
	get_ffn(ffn, argv[0]);
	if (write_pub_hid_file(ffn, stdout)) {
		fprintf(stderr, "Couldn't create public HID file\n");
		return -1;
	}

	return 0;
}

/* read_hid_file - load @filename into @addr and @ppkey.
 * (*ppkey) must not be allocated; it'll be allocated if no error is found.
 * @is_prv must be true if the file holds a private key.
 *
 * RETURN
 *	returns zero on success; otherwise a negative number.
 */
static int read_hid_file(const char *filename, int is_prv,
		struct xia_addr *addr, PPK_KEY **ppkey)
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

static int do_addaddr(int argc, char **argv)
{
	char ffn[PATH_MAX];
	struct xia_addr addr;
	PPK_KEY *pkey;

	if (argc != 3) {
		fprintf(stderr, "Wrong number of parameters\n");
		return usage();
	}
	if (strcmp(argv[1], "dev")) {
		fprintf(stderr, "Wrong parameters\n");
		return usage();
	}
	
	get_ffn(ffn, argv[0]);
	if (read_hid_file(ffn, 1, &addr, &pkey)) {
		fprintf(stderr, "Couldn't read private HID file\n");
		return -1;
	}

	/* XXX There is no way of printing addr out at this point. */
	assert(!write_prvpem(pkey, stdout));
	/* TODO */
	fprintf(stderr, "TODO: Assign address to interface %s(%u)!\n",
		argv[2], ll_name_to_index(argv[2]));

	ppk_free_key(pkey);
	return 0;
}

static int do_help(int argc, char **argv)
{
	usage();
	exit(-1);
}

static const struct cmd cmds[] = {
	{ "new",	do_newhid	},
	{ "getpub",	do_getpub	},
	{ "addaddr",	do_addaddr	},
	{ "help",	do_help		},
	{ 0 }
};

int do_hid(int argc, char **argv)
{
	if (argc < 1) {
		/* TODO */
		fprintf(stderr, "TODO: List all interfaces!\n");
		return 0;
	}

	assert(!init_ppal_map());
	assert(!ll_init_map(&rth));
	return do_cmd(cmds, "Command", "xip hid help", argc, argv);
}
