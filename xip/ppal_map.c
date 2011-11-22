#include <stdio.h>
#include <assert.h>
#include <ctype.h>
#include <linux/types.h>
#include <asm-generic/errno-base.h>
#include <asm/byteorder.h>
#include <net/xia_dag.h>

#include "ppal_map.h"

#ifndef PRINCIPAL_FILENAME
#define PRINCIPAL_FILENAME	"/etc/xia/principals"
#endif

static void add_map(const char *name, xid_type_t type)
{
	int rc = ppal_add_map(name, type);
	switch (rc) {
	case -EINVAL:
		fprintf(stderr, "Warning: ignoring invalid principal name "
			"or type '%s'(%x)\n", name, __be32_to_cpu(type));
		break;
	case -ESRCH:
		fprintf(stderr, "Warning: ignoring duplicated "
			"principal '%s'(%x)\n",	name, type);
		break;
	case -ENOMEM:
		fprintf(stderr, "Warning: ignoring principal '%s'(%x) due to "
			"lack of memory\n", name, type);
		break;
	default:
		if (rc < 0)
			fprintf(stderr, "Warning: ignoring principal '%s'(%x) "
				"due to unknown error (%i)\n", name, type, rc);
		break;
	}
}

static int is_blank(const char *str)
{
	while (isspace(*str))
		str++;
	if (*str == '\0')
		return 1;
	return 0;
}

#define BUF_SIZE 256
static int load_ppal_map(void)
{
	FILE *f;
	/* buf and name must have the same size to properly handle cases like
	 * this line: "a2345678901234567890... 99\n"
	 */
	char buf[BUF_SIZE], name[BUF_SIZE];
	char format1[64], format2[64];

	f = fopen(PRINCIPAL_FILENAME, "r");
	if (!f) {
		fprintf(stderr, "Warning: couldn't read file: %s\n",
			PRINCIPAL_FILENAME);
		return -1;
	}

	/* The minus one ensures that scanf will always be able to add
	 * a traling '\0'.
	 */
	sprintf(format1, "%%%lu[^#\n]", sizeof(buf) - 1);
	sprintf(format2, "%%%lus%%i", sizeof(name) - 1);
	while (!feof(f)) {
		int matches, ch;
		__u32 cpu_ty;

		matches = fscanf(f, format1, buf);
		if (matches < 0)
			break;
		else if (matches == 0)
			buf[0] = '\0';

		/* Take the rest of the line off. */
		do {
			ch = getc(f);
		} while (ch != EOF && ch != '\n');

		/* Verify format. */
		if (is_blank(buf))
			continue;
		if (sscanf(buf, format2, name, &cpu_ty) < 2) {
			fprintf(stderr, "Warning: %s: invalid input: %s\n",
				PRINCIPAL_FILENAME, buf);
			continue;
		}

		add_map(name, __cpu_to_be32(cpu_ty));
	}
	fclose(f);
	return 0;
}

int init_ppal_map(void)
{
	return load_ppal_map();
}

void print_xia_addr(const struct xia_addr *addr)
{
	char buf[XIA_MAX_STRADDR_SIZE];
	assert(xia_ntop(addr, buf, XIA_MAX_STRADDR_SIZE, 1) >= 0);
	printf("%s\n", buf);
}

void print_xia_xid(const struct xia_xid *xid)
{
	char buf[XIA_MAX_STRXID_SIZE];
	assert(xia_xidtop(xid, buf, XIA_MAX_STRXID_SIZE) >= 0);
	printf("%s", buf);
}
