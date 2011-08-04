#include <assert.h>
#include <limits.h>
#include <net/xia.h>

#include "hid.h"
#include "ppk.h"

int main(void)
{
	char ffn[PATH_MAX];
	struct xia_addr addr;
	PPK_KEY *pkey;

	assert(!init_ppk());
	assert(!int_ppal_map());

	get_ffn(ffn, "./test.hid");
	assert(!write_new_hid_file(ffn));
	assert(!write_pub_hid_file(ffn, stdout));

	assert(!read_hid_file(ffn, 1, &addr, &pkey));
	/* XXX There is no way of printing addr out at this point. */
	assert(!write_prvpem(pkey, stdout));

	end_ppk();
	return 0;
}
