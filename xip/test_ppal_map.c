#include <stdio.h>
#include <assert.h>

#include "ppal_map.h"

int main(void)
{
	int_ppal_map();

	assert(ppal_name_to_type("hid"));
	assert(ppal_name_to_type("Sid"));
	assert(!ppal_name_to_type(""));
	assert(!ppal_name_to_type("XXX"));

	return 0;
}
