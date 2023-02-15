#include <stdio.h>
#include <stdint.h>

void print_mac(uint8_t* mac);

int send_packet(struct rte_mempool *mbuf_pool,
                struct rte_ether_addr *src_mac,
                struct rte_ether_addr *dst_mac,
                uint16_t port, int value, int msg_len);

uint32_t checksum_be(unsigned char *buf, uint32_t nbytes, uint32_t sum);