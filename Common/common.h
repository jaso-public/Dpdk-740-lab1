#include <stdio.h>
#include <stdint.h>

#define max(a,b) \
   ({ __typeof__ (a) _a = (a); \
       __typeof__ (b) _b = (b); \
     _a > _b ? _a : _b; })

#define BILLION (1000000000L)

#define RX_RING_SIZE 1024
#define TX_RING_SIZE 1024

uint64_t raw_time();

void print_mac(uint8_t* mac);

int send_packet(struct rte_mempool *mbuf_pool,
                struct rte_ether_addr *src_mac,
                struct rte_ether_addr *dst_mac,
                uint16_t port, int32_t value, uint32_t msg_len);

int receive_packet(struct rte_mbuf *packet,
                   struct rte_ether_addr *src_mac,
                   struct rte_ether_addr *dst_mac,
                   uint16_t *port, int32_t *value, uint32_t *msg_len);

int port_init(uint16_t port, struct rte_mempool *mbuf_pool, struct rte_ether_addr *my_mac);