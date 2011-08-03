#include <assert.h>
#include <limits.h>
#include "hid.h"

int main(void)
{
	char ffn[PATH_MAX];
	get_ffn(ffn, "./test.hid");
	assert(!write_new_hid_file(ffn));
	assert(!write_pub_hid_file(ffn, stdout));
	return 0;
}
