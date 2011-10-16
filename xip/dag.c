#include <assert.h>
#include <linux/kernel.h>

#include "dag.h"
#include "ppal_map.h"

/*
 * xia_pton and its auxiliares functions
 */

static inline void next(const char **pp, size_t *pleft)
{
	(*pp)++;
	(*pleft)--;
}

static inline int read_sep(const char **pp, size_t *pleft, char sep)
{
	if (*pleft <= 0 || **pp != sep)
		return -1;
	next(pp, pleft);
	return 0;
}

static int read_invalid_flag(const char **pp, size_t *pleft, int *invalid_flag)
{
	int inv_flag;
	if (*pleft <= 0) /* No XIA address is an empty string. */
		return -1;
	inv_flag = **pp == '!';
	if (inv_flag)
		next(pp, pleft);
	if (invalid_flag)
		*invalid_flag = inv_flag;
	return 0;
}

static inline int ascii_to_int(char ch)
{
	if (ch >= '0' && ch <= '9') {
		return ch - '0';
	} else if (ch >= 'A' && ch <= 'Z') {
		return ch - 'A'; 
	} else if (ch >= 'a' && ch <= 'z') {
		return ch - 'a';
	} else
		return 64;
}

static int read_be32(const char **pp, size_t *pleft, __be32 *value)
{
	__u32 result = 0;
	int i = 0;

	while (*pleft >= 1 && isxdigit(**pp) && i < 8) {
		result = (result << 4) + ascii_to_int(**pp);
		next(pp, pleft);
		i++;
	}
	*value = __cpu_to_be32(result);
	return i;
}

static inline int isname(char ch)
{
	return isgraph(ch) && ch != '-';
}

static int read_name(const char **pp, size_t *pleft, char *name, int len)
{
	int i = 0;
	int last = len - 1;
	
	assert(len >= 1);

	while (*pleft >= 1 && isname(**pp) && i < last) {
		name[i] = **pp;
		next(pp, pleft);
		i++;
	}
	name[i] = '\0';
	return i;
}

static int read_type(const char **pp, size_t *pleft, xid_type_t *pty)
{
	BUILD_BUG_ON(sizeof(xid_type_t) != 4);

	/* There must be at least a digit! */
	if (read_be32(pp, pleft, pty) < 1) {
		char name[MAX_PPAL_NAME_SIZE];
		/* There must be at least a symbol. */
		if (read_name(pp, pleft, name, sizeof(name)) < 1)
			return -1;
		*pty = ppal_name_to_type(name);
	}

	/* Not A Type is not a type! */
	if (xia_is_nat(*pty))
		return -1;

	return 0;
}

static int read_xid(const char **pp, size_t *pleft, __u8 *xid)
{
	int i;
	__be32 *pxid = (__be32 *)xid;
	BUILD_BUG_ON(XIA_XID_MAX != 20);

	for (i = 0; i < 5; i++) {
		if (read_be32(pp, pleft, pxid++) != 8)
			return -1;
	}
	return 0;
}

static int read_edges(const char **pp, size_t *pleft, __u8 *edge, int ignore_ce)
{
	int i;

	for (i = 0; i < XIA_OUTDEGREE_MAX; i++)
		edge[i] = XIA_EMPTY_EDGE;
	if (read_sep(pp, pleft, '-')) {
		/* No edges, we're done. */
		return 0;
	}

	for (i = 0; i < XIA_OUTDEGREE_MAX; i++) {
		int ce = 0;
		int e = XIA_EMPTY_EDGE;

		if (!read_sep(pp, pleft, '>'))
			ce = ignore_ce ? 0 : XIA_CHOSEN_EDGE;

		if (*pleft >= 1 && isalnum(**pp)) {
			e = ascii_to_int(**pp);
			next(pp, pleft);
		} else if (!read_sep(pp, pleft, '*')) {
			/* e is already equal to XIA_EMPTY_EDGE. */
		} else if (i == 0) {
			/* At least an edge is necessary since we saw a '-'.
			 * We don't support '+' because
			 * one cannot know which value to associate to it.
			 */
			return -1;
		} else {
			break;
		}
		edge[i] = ce | e;
	}
	return 0;
}

static int read_row(const char **pp, size_t *pleft, struct xia_row *row,
	int ignore_ce)
{
	if (read_type(pp, pleft, &row->s_xid_type))
		return -1;
	if (read_sep(pp, pleft, '-'))
		return -1;
	if (read_xid(pp, pleft, row->s_xid))
		return -1;
	if (read_edges(pp, pleft, row->s_edge.a, ignore_ce))
		return -1;
	return 0;
}

static int read_node_sep(const char **pp, size_t *pleft)
{
	if (read_sep(pp, pleft, ':'))
		return -1;
	read_sep(pp, pleft, '\n');
	return 0;
}

int xia_pton(const char *src, size_t srclen, struct xia_addr *dst,
	int ignore_ce, int *invalid_flag)
{
	const char *p = src;
	size_t left = srclen;
	int i = 0;
 
	if (read_invalid_flag(&p, &left, invalid_flag))
		return -1;

	do {
		if (read_row(&p, &left, &dst->s_row[i], ignore_ce))
			return -1;
		if (++i >= XIA_NODES_MAX)
			return -1;
	} while (!read_node_sep(&p, &left));

	/* It's okay to have a newline on the last line. */
	read_sep(&p, &left, '\n');

	/* A whole address must be parsed. */
	if (left != 0 && *p != '\0')
		return -1;
	return srclen - left;
}

int xia_ptoxid(const char *src, size_t srclen, struct xia_xid *dst)
{
	const char *p = src;
	size_t left = srclen;
 
	if (read_type(&p, &left, &dst->xid_type))
		return -1;
	if (read_sep(&p, &left, '-'))
		return -1;
	if (read_xid(&p, &left, dst->xid_id))
		return -1;

	/* A whole XID must be parsed. */
	if (left != 0 && *p != '\0')
		return -1;
	return srclen - left;
}

int xia_ptoid(const char *src, size_t srclen, struct xia_xid *dst)
{
	const char *p = src;
	size_t left = srclen;
 
	if (read_xid(&p, &left, dst->xid_id))
		return -1;

	/* A whole ID must be parsed. */
	if (left != 0 && *p != '\0')
		return -1;
	return srclen - left;
}
