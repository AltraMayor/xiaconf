#include <stdio.h>
#include <assert.h>
#include <net/xia_dag.h>

#include "ppal_map.h"

int main(void)
{
	xid_type_t ty;
	assert(!init_ppal_map("../etc-test/xia/principals"));

	assert(!ppal_name_to_type("nat", &ty));
	assert(!ppal_name_to_type("hid", &ty));
	assert(!ppal_name_to_type("Sid", &ty));
	assert(ppal_name_to_type("", &ty));
	assert(ppal_name_to_type("XXX", &ty));

	return 0;
}
