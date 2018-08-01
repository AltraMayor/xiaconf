#include "globals.h"

struct config nwpd_config = {
        .try_announce_period = 2,
        .monitor_ping_period = 5,
        .monitor_ack_timeout = 5,
        .monitor_investigative_ack_timeout = 5,
        .monitor_investigative_neigh_count = 10,
};
