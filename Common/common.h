#include <stdio.h>
#include <stdint.h>

#define BILLION (1000000000L)

uint64_t raw_time();

void print_mac(uint8_t* mac);

int send_packet(struct rte_mempool *mbuf_pool,
                struct rte_ether_addr *src_mac,
                struct rte_ether_addr *dst_mac,
                uint16_t port, int value, int msg_len);

int receive_packet(struct rte_mbuf *packet,
                struct rte_ether_addr *src_mac,
                struct rte_ether_addr *dst_mac,
                uint16_t *port, int *value, int *msg_len);
