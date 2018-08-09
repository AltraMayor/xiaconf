#include <net/xia.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <sys/socket.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <signal.h>

#include "uthash.h"

#include "log.h"
#include "nwp.h"
#include "timer.h"
#include "monitor.h"
#include "globals.h"
#include "neigh.h"

struct host_clock *hosts_table = NULL;
pthread_rwlock_t hosts_table_lock;

static void monitor_start_ping_process(union sigval);

void init_monitor()
{
        pthread_rwlock_init(&hosts_table_lock, NULL);

        struct timespec spec = {.tv_sec = nwpd_config.monitor_ping_period};
        timer_t t = create_timer(monitor_start_ping_process, NULL);
        set_timer(&spec, t, true);
}

static int host_clock_cmp(void *v1, void *v2)
{
        struct host_clock *h1 = v1, *h2 = v2;
        if (h1->clock < h2->clock)
                return -1;
        if (h1->clock == h2->clock)
                return 0;
        return 1;
}

/* addr, ether_xid, and ad_xids should be malloc-allocated */
void monitor_add_host(struct sockaddr_ll *addr, struct xia_xid *ether_xid,
                      struct xia_xid **ad_xids, int n_ads)
{
        struct host_clock *tmp, *host;
        pthread_rwlock_wrlock(&hosts_table_lock);
        HASH_FIND(hh, hosts_table, addr->sll_addr, addr->sll_halen, tmp);
        if (tmp == NULL) {
                host = calloc(1, sizeof(struct host_clock));
                host->addr = addr;
                host->ether_xid = ether_xid;
                host->ad_xids = ad_xids;
                host->n_ads = n_ads;
                host->haddr = (char *)addr->sll_addr;
                pthread_rwlock_init(&host->lock, NULL);

                HASH_ADD_KEYPTR(hh, hosts_table, addr->sll_addr, addr->sll_halen, host);
                HASH_SORT(hosts_table, host_clock_cmp);
                nwpd_logf(LOG_LEVEL_INFO, "Added neighbor %s\n", xid_str(ether_xid));
        }
        pthread_rwlock_unlock(&hosts_table_lock);
}

static void remove_neighbor(struct host_clock *host)
{
        nwpd_logf(LOG_LEVEL_INFO, "Removing neighbor %s\n", xid_str(host->ether_xid));
        int i = 0;
        modify_neighbor(host->ether_xid, false);
        for (i = 0; i < host->n_ads; i++)
                modify_route(host->ad_xids[i], NULL);
}

inline static size_t monitor_size()
{
        return sizeof(struct nwp_common_hdr) + 2 * sizeof(uint8_t)
                + sizeof(int32_t) + 2 * ETH_ALEN * sizeof(uint8_t);
}

inline static size_t monitor_investigate_size()
{
        return monitor_size() + ETH_ALEN * sizeof(uint8_t);
}


static struct host_clock *get_host(char *haddr)
{
        struct host_clock *host;
        pthread_rwlock_rdlock(&hosts_table_lock);
        HASH_FIND(hh, hosts_table, haddr, ETH_ALEN, host);
        pthread_rwlock_unlock(&hosts_table_lock);
        return host;
}

void send_monitor(int socket, struct sockaddr_ll *addr, uint8_t type,
                  char *src_addr, char *dest_addr)
{
        nwpd_logf(LOG_LEVEL_DEBUG, "Sending monitor packet %d\n", type);
        struct nwp_monitor packet;
        char *buf = calloc(1, monitor_size()), *cur_buf = buf;
        size_t elem_size = sizeof(struct nwp_common_hdr) + 2 * sizeof(uint8_t)
                + sizeof(int32_t);

        packet.common.version = 0x01;
        packet.common.type = type;

        packet.haddr_len = ETH_ALEN;
        packet.reserved = 0;
        packet.sender_clock = (int32_t)time(NULL);
        memcpy(cur_buf, &packet, elem_size);
        cur_buf += elem_size;

        memcpy(cur_buf, src_addr, ETH_ALEN);
        cur_buf += ETH_ALEN;
        memcpy(cur_buf, dest_addr, ETH_ALEN);

        if (sendto(socket, buf, monitor_size(), 0, (struct sockaddr *)addr,
                   sizeof(*addr)) == -1)
                nwpd_perror("sendto");
        free(buf);
}

void send_monitor_investigate(int socket, struct sockaddr_ll *addr,
                              uint8_t type, char *src_addr,
                              char *dest_addr, char *investigate_addr)
{
        struct nwp_monitor_investigate packet;
        char *buf = calloc(1, monitor_investigate_size()), *cur_buf = buf;
        size_t elem_size = sizeof(struct nwp_common_hdr) + 2 * sizeof(uint8_t)
                + sizeof(int32_t);
        packet.common.version = 0x01;
        packet.common.type = type;

        packet.haddr_len = ETH_ALEN;
        packet.reserved = 0;
        packet.sender_clock = (int32_t)time(NULL);
        memcpy(cur_buf, &packet, elem_size);
        cur_buf += elem_size;

        memcpy(cur_buf, src_addr, ETH_ALEN);
        cur_buf += ETH_ALEN;
        memcpy(cur_buf, dest_addr, ETH_ALEN);
        cur_buf += ETH_ALEN;
        memcpy(cur_buf, investigate_addr, ETH_ALEN);

        if (sendto(socket, buf, monitor_investigate_size(), 0,
                   (struct sockaddr *)addr, sizeof(*addr)) == -1)
                perror("sendto");
        free(buf);
}

void process_monitor(struct sockaddr_ll *addr,
                     struct nwp_monitor *packet)
{
        if (addr->sll_halen != packet->haddr_len) {
                nwpd_logf(LOG_LEVEL_ERROR, "hardware address length is different in the packet and the sender's sockaddr_ll value, discarding\n");
                return;
        }

        struct host_clock *host = get_host((char *)addr->sll_addr);
        if (host == NULL)
                return;

        switch (packet->common.type) {
        case NWP_MONITOR_PING:
                nwpd_logf(LOG_LEVEL_DEBUG, "Got a ping from %s\n", xid_str(host->ether_xid));
                pthread_rwlock_wrlock(&host->lock);
                host->clock = packet->sender_clock;
                pthread_rwlock_unlock(&host->lock);
                send_monitor(eth_socket, addr, NWP_MONITOR_ACK,
                             (char *)packet->haddr_dest, (char *)addr->sll_addr);
                break;
        default: /* NWP_MONITOR_ACK */
                nwpd_logf(LOG_LEVEL_DEBUG, "Got ack from %s\n", xid_str(host->ether_xid));
                pthread_rwlock_wrlock(&host->lock);
                if (host->waiting_for_ack) {
                        host->waiting_for_ack = false;
                        host->waiting_for_investigative_ack = false;
                        host->clock = packet->sender_clock;
                        timer_delete(host->timeout);
                }
                pthread_rwlock_unlock(&host->lock);
                break;
        }

}

void process_monitor_investigate(struct sockaddr_ll *addr,
                                 struct nwp_monitor_investigate *packet)
{
        if (addr->sll_halen != packet->haddr_len) {
                nwpd_logf(LOG_LEVEL_ERROR, "hardware address length is different in the packet and the sender's sockaddr_ll value, discarding\n");
                return;
        }

        struct host_clock *host = get_host((char *)addr->sll_addr);
        if (host == NULL)
                return;
        switch (packet->common.type) {
        case NWP_MONITOR_PING_REQUEST:
                send_monitor_investigate(eth_socket, addr,
                                         NWP_MONITOR_INVESTIGATE_PING,
                                         (char *)packet->haddr_src,
                                         (char *)packet->haddr_investigate,
                                         (char *)packet->haddr_investigate);
                break;
        default: /* NWP_MONITOR_INVESTIGATE_PING */
                if (memcmp(if_hwaddr, packet->haddr_investigate, ETH_ALEN) != 0)
                        return;
                if (memcmp(if_hwaddr, packet->haddr_dest, ETH_ALEN) != 0)
                        return;
                send_monitor(eth_socket, addr, NWP_MONITOR_ACK,
                             (char *)if_hwaddr, (char *)packet->haddr_src);
                send_announce(eth_socket, &broadcast_addr);
                break;
        }

}

/* Call only when hosts_table_lock is held. */
static struct host_clock *get_random_host()
{
        int r, i, count, unavail_host;
        bool avail;
        struct host_clock *h;

        pthread_rwlock_rdlock(&hosts_table_lock);
        while(1) {
                i = unavail_host = 0;
                h = NULL;
                count = HASH_COUNT(hosts_table);
                if (count == 0)
                        break;

                r = rand() % count;
                for (h = hosts_table;;h=h->hh.next) {
                        pthread_rwlock_rdlock(&h->lock);
                        avail = !h->waiting_for_investigative_ack && !h->waiting_for_ack;
                        pthread_rwlock_unlock(&h->lock);

                        if (!avail)
                                unavail_host++;
                        if (i++ == r)
                                break;

                }
                assert(h != NULL);
                if (avail)
                        break;
                if (unavail_host == count) {
                        h = NULL;
                        break;
                }
        }
        pthread_rwlock_unlock(&hosts_table_lock);
        return h;
}

static void monitor_on_investigative_ack_timeout(union sigval s)
{
        struct host_clock *host = (struct host_clock *)s.sival_ptr;

        remove_neighbor(host);

        pthread_rwlock_wrlock(&hosts_table_lock);
        HASH_DEL(hosts_table, host);

        pthread_rwlock_wrlock(&host->lock);
        free(host->addr);
        free(host->ether_xid);
        pthread_rwlock_unlock(&host->lock);

        pthread_rwlock_destroy(&host->lock);
        free(host);

        pthread_rwlock_unlock(&hosts_table_lock);
}

static void monitor_on_ack_timeout(union sigval s)
{
        struct host_clock *host = (struct host_clock *)s.sival_ptr, *h;
        int i = 0;

        nwpd_logf(LOG_LEVEL_DEBUG, "Ack timeout %s\n", xid_str(host->ether_xid));

        pthread_rwlock_wrlock(&host->lock);
        host->waiting_for_investigative_ack = true;
        for (h = hosts_table;h != NULL;h=h->hh.next) {
                if (h == host)
                        continue;
                pthread_rwlock_rdlock(&h->lock);
                if (!h->waiting_for_investigative_ack
                    && !h->waiting_for_ack) {
                        i++;
                        send_monitor_investigate(eth_socket, h->addr,
                                                 NWP_MONITOR_PING_REQUEST,
                                                 (char *)if_hwaddr, h->haddr, host->haddr);
                }
                pthread_rwlock_unlock(&h->lock);
                if (i == nwpd_config.monitor_investigative_neigh_count)
                        break;
        }
        host->timeout = create_timer(monitor_on_investigative_ack_timeout, host);
        struct timespec spec = {.tv_sec = nwpd_config.monitor_investigative_ack_timeout};
        set_timer(host->timeout, &spec, false);
        pthread_rwlock_unlock(&host->lock);
}

static void monitor_start_ping_process(union sigval s)
{
        struct host_clock *h = get_random_host();

        if (h == NULL)
                return;

        pthread_rwlock_wrlock(&h->lock);
        h->waiting_for_ack = true;
        h->timeout = create_timer(monitor_on_ack_timeout, h);
        struct timespec spec = {.tv_sec = nwpd_config.monitor_ack_timeout};
        set_timer(h->timeout, &spec, false);
        nwpd_logf(LOG_LEVEL_DEBUG, "Sending periodic ping to %s\n", xid_str(h->ether_xid));
        send_monitor(eth_socket, h->addr, NWP_MONITOR_PING, (char *)if_hwaddr, h->haddr);
        pthread_rwlock_unlock(&h->lock);
}
