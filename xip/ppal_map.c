#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include <linux/types.h>
#include <asm/byteorder.h>

#include "ppal_map.h"

#ifndef PRINCIPAL_FILENAME
#define PRINCIPAL_FILENAME	"/etc/xia/principals"
#endif

/* This constant must be a power of 2. */
#define PPAL_MAP_SIZE	1024

struct ppal_list {
	struct ppal_list	*next;
	__u8			name[MAX_PPAL_NAME_SIZE];
	xid_type_t		type;
};

static struct ppal_list *ppal_head[PPAL_MAP_SIZE];

__u32 djb_case_hash(const __u8 *str)
{
	__u32 hash = 5381;
	const __u8 *p = str;

	while (*p) {
		hash = ((hash << 5) + hash) + tolower(*p);
		p++;
	}
	return hash;
}

static inline struct ppal_list **p_ppalhead(const __u8 *name)
{
	return &ppal_head[djb_case_hash(name) & (PPAL_MAP_SIZE - 1)];
}

static inline struct ppal_list *ppalhead(const __u8 *name)
{
	return *p_ppalhead(name);
}

xid_type_t ppal_name_to_type(const __u8 *name)
{
	const struct ppal_list *entry;

	for (entry = ppalhead(name); entry; entry = entry->next) {
		if (!strcasecmp(entry->name, name))
			return entry->type;
	}
	return XIDTYPE_NAT;
}

static int is_name_valid(const __u8 *name)
{
	int left = MAX_PPAL_NAME_SIZE;

	if (!isalpha(*name))
		return 0;
	name++;
	left--;

	while (left > 0 && (isalnum(*name) || *name == '_')) {
		name++;
		left--;
	}

	if (left > 0 && *name == '\0')
		return 1;
	return 0;
}

static inline void lowerstr(__u8 *s)
{
	while(*s) {
		*s = tolower(*s);
		s++;
	}
}

static void add_map(const __u8 *name, xid_type_t type)
{
	struct ppal_list **pentry, *entry;

	if (!is_name_valid(name)) {
		fprintf(stderr, "Warning: ignoring invalid principal name "
			"`%s'\n", name);
		return;
	}

	/* Avoid duplicates. */
	for (pentry = p_ppalhead(name); (entry = *pentry);
		pentry = &entry->next) {
		if (!strcasecmp(entry->name, name)) {
			fprintf(stderr, "Warning: ignoring duplicated "
				"principal `%s' (previously defined type %x) "
				"with type %x\n",
				name, entry->type, type);
			return;
		}
	}

	/* Initialize new entry. */
	entry = malloc(sizeof(*entry));
	if (!entry)
		return;
	strncpy(entry->name, name, sizeof(entry->name));
	entry->name[sizeof(entry->name) - 1] = '\0';
	lowerstr(entry->name);
	entry->type = type;

	/* Add entry to head of list. */
	entry->next = *pentry;
	*pentry = entry;
}

static int is_blank(const __u8 *str)
{
	while (isspace(*str))
		str++;
	if (*str == '\0')
		return 1;
	return 0;
}

#define BUF_SIZE 256
static void load_ppal_map(void)
{
	FILE *f;
	/* buf and name must have the same size to properly handle cases like
	 * this line: "a2345678901234567890... 99\n"
	 */
	__u8 buf[BUF_SIZE], name[BUF_SIZE];
	__u8 format1[64], format2[64];

	f = fopen(PRINCIPAL_FILENAME, "r");
	if (!f) {
		fprintf(stderr, "Warning: couldn't read file: %s\n",
			PRINCIPAL_FILENAME);
		return;
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
}

void int_ppal_map(void)
{
	load_ppal_map();
}
