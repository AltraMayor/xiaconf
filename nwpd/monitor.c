#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <sys/socket.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <stdlib.h>
#include <time.h>
#include "nwp.h"

struct host_clock {
        _Atomic atomic_int_least32_t clock;
        _Atomic atomic_bool waiting_for_reply;
        char haddr[ETH_ALEN];
        struct host_clock *next;
        struct host_clock *prev;
};

struct host_clock *hosts;
pthread_rwlock_t hosts_lock;

void init_hosts_lock()
{
        pthread_rwlock_init(&hosts_lock, NULL);
}

/* Call only when hosts_lock is write held */
static void init_hosts_list(char *haddr)
{
        hosts = calloc(1, sizeof(struct host_clock));
        memcpy(hosts->haddr, haddr, ETH_ALEN);
}

static struct host_clock *get_or_create_host(char *haddr)
{
        pthread_rwlock_wrlock(&hosts_lock);
        if (hosts == NULL) {
                init_hosts_list(haddr);
                pthread_rwlock_unlock(&hosts_lock);
                return hosts;
        }


        struct host_clock *host = hosts, *prev;
        while (hosts != NULL) {
                prev = host;
                if (memcmp(host->haddr, haddr, ETH_ALEN) == 0) {
                        pthread_rwlock_unlock(&hosts_lock);
                        return host;
                }

                host = host->next;
        }
        /* hosts == NULL */
        host = prev->next = calloc(1, sizeof(struct host_clock));
        host->prev = prev;
        pthread_rwlock_unlock(&hosts_lock);
        memcpy(host->haddr, haddr, ETH_ALEN);
        return host;
}

const inline size_t monitor_size()
{
        return sizeof(struct nwp_common_hdr) + 2 * sizeof(uint8_t)
                + sizeof(int32_t) + 2 * ETH_ALEN * sizeof(uint8_t);
}

const inline size_t monitor_investigate_size()
{
        return monitor_size() + ETH_ALEN * sizeof(uint8_t);
}

static void send_monitor(int socket, struct sockaddr_ll *addr, uint8_t type,
                         char *src_addr, char *dest_addr)
{
        struct nwp_monitor packet;
        char *buf = calloc(1, monitor_size()), *cur_buf = buf;
        size_t elem_size = sizeof(struct nwp_common_hdr) + 2*sizeof(uint8_t)
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
                   sizeof(*addr)) == -1) {
                perror("sendto");
        }
        free(buf);
}

static void send_monitor_investigate(int socket, struct sockaddr_ll *addr,
                                     uint8_t type, char *src_addr,
                                     char *dest_addr, char *investigate_addr)
{
        struct nwp_monitor_investigate packet;
        char *buf = calloc(1, monitor_investigate_size()), *cur_buf = buf;
        size_t elem_size = sizeof(struct nwp_common_hdr) + 2*sizeof(uint8_t)
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
                   (struct sockaddr *)addr, sizeof(*addr)) == -1) {
                perror("sendto");
        }
        free(buf);
}

static struct host_clock *get_host(char *haddr)
{
        pthread_rwlock_rdlock(&hosts_lock);
        struct host_clock *host = hosts;
        while (host != NULL) {
                if (memcmp (host->haddr, haddr, ETH_ALEN) == 0) {
                        pthread_rwlock_unlock(&hosts_lock);
                        return host;
                }
                host = host->next;
        }

        pthread_rwlock_unlock(&hosts_lock);
        return NULL;
}

void process_monitor(struct sockaddr_ll *addr, struct nwp_monitor *packet)
{
        if (addr->sll_halen != packet->haddr_len) {
                fprintf(stderr, "hardware address length is different in the packet and the sender's sockaddr_ll value, discarding\n");
                return;
        }

        struct host_clock *host;

        switch (packet->common.type) {
        case NWP_MONITOR_PING:
                host = get_or_create_host(addr->sll_halen);
                atomic_store(&host->clock, packet->sender_clock);

                break;
        default: /* NWP_MONITOR_ACK */
                host = get_host(addr->sll_halen);
                if (host == NULL || !atomic_load(&host->waiting_for_reply))
                        /* Got an unexpected ack, discard */
                        return;

                break;
        }
}
