#ifndef _GLOBALS_H
#define _GLOBALS_H
#include <libmnl/libmnl.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>

extern struct mnl_socket *xia_nl_socket;
extern struct sockaddr_ll broadcast_addr;
extern int eth_socket;
extern uint8_t if_hwaddr[ETH_ALEN];

struct config {
        /* The hardware interface to listen on. */
        char *interface;
        /* The minimum log level. */
        int log_level;
        /* The time period (in seconds) for try announcing to the network. */
        int try_announce_period;
        /* The time period (in seconds) for attemping to ping a neighbor. */
        int monitor_ping_period;
        int monitor_ack_timeout;
        /* The timeout period for an investigative ack before nwpd removes
         a neighbor. */
        int monitor_investigative_ack_timeout;
        /* The number of neighbours nwpd sends an investigative ping request to
           on a timeout. */
        int monitor_investigative_neigh_count;
};

extern struct config nwpd_config;

#endif /* _GLOBALS_H */
