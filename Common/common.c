

#include <stdint.h>
#include <stdlib.h>
#include <inttypes.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_cycles.h>
#include <rte_lcore.h>
#include <rte_mbuf.h>
#include <rte_udp.h>
#include <rte_ip.h>

#include <rte_common.h>

#include "common.h"

/**
 * returns the number of nanoseconds since the beginning oof the epoch (1/1/1970)
 */
uint64_t raw_time() {
    struct timespec tstart;
    clock_gettime(CLOCK_MONOTONIC, &tstart);
    return ((uint64_t)tstart.tv_sec)*BILLION + ((uint64_t)tstart.tv_nsec);
}


void print_mac(uint8_t* mac) {
    printf("%02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1], mac[2], mac[3], mac[4] ,mac[5]);
}



uint32_t checksum_be(unsigned char *buf, uint32_t nbytes, uint32_t sum) {
    unsigned int     i;

    /* Checksum all the pairs of bytes first. */
    for (i = 0; i < (nbytes & ~1U); i += 2) {
        sum += (uint16_t)ntohs(*((uint16_t *)(buf + i)));
        if (sum > 0xFFFF)
            sum -= 0xFFFF;
    }

    if (i < nbytes) {
        sum += buf[i] << 8;
        if (sum > 0xFFFF)
            sum -= 0xFFFF;
    }

    sum = ~sum & 0xFFFF;
    return htons(sum);
}


int send_packet(struct rte_mempool *mbuf_pool,
                struct rte_ether_addr *src_mac,
                struct rte_ether_addr *dst_mac,
                uint16_t port, int32_t value, uint32_t msg_len) {

    printf("SENDING port:%d, value:%d, msg_len:%d\n", port, value, msg_len);

    struct rte_mbuf *pkt;
    uint8_t *ptr;
    size_t header_size;

    // the size of the udp payload.
    // the 'protocol' value (4 bytes) and the actual message bytes
    int payload_size = sizeof(int32_t) + msg_len;

    pkt = rte_pktmbuf_alloc(mbuf_pool);
    if (pkt == NULL) {
        printf("Error allocating tx mbuf\n");
        return -EINVAL;
    }

    ptr = rte_pktmbuf_mtod(pkt, uint8_t *);
    header_size = 0;

    /* add in an ethernet header */
    struct rte_ether_hdr *eth_hdr = (struct rte_ether_hdr *)ptr;
    ptr += sizeof(*eth_hdr);
    header_size += sizeof(*eth_hdr);

    rte_ether_addr_copy(src_mac, &eth_hdr->src_addr);
    rte_ether_addr_copy(dst_mac, &eth_hdr->dst_addr);
    eth_hdr->ether_type = rte_be_to_cpu_16(RTE_ETHER_TYPE_IPV4);

    // move the ptr and update the header size

    /* add in ipv4 header*/
    struct rte_ipv4_hdr *ipv4_hdr = (struct rte_ipv4_hdr *)ptr;
    ptr += sizeof(*ipv4_hdr);
    header_size += sizeof(*ipv4_hdr);

    ipv4_hdr->version_ihl = 0x45;
    ipv4_hdr->type_of_service = 0x0;
    ipv4_hdr->total_length = rte_cpu_to_be_16(sizeof(struct rte_ipv4_hdr) + sizeof(struct rte_udp_hdr) + payload_size);
    ipv4_hdr->packet_id = rte_cpu_to_be_16(1);
    ipv4_hdr->fragment_offset = 0;
    ipv4_hdr->time_to_live = 64;
    ipv4_hdr->next_proto_id = IPPROTO_UDP;
    ipv4_hdr->src_addr = rte_cpu_to_be_32(0x7f000001);
    ipv4_hdr->dst_addr = rte_cpu_to_be_32(0x7f000001);

    uint32_t ipv4_checksum = checksum_be((unsigned char *)ipv4_hdr, sizeof(struct rte_ipv4_hdr), 0);
    ipv4_hdr->hdr_checksum = rte_cpu_to_be_32(ipv4_checksum);

    /* add in UDP hdr*/
    struct rte_udp_hdr *udp_hdr = (struct rte_udp_hdr *)ptr;
    ptr += sizeof(*udp_hdr);
    header_size += sizeof(*udp_hdr);

    udp_hdr->src_port = rte_cpu_to_be_16(port);
    udp_hdr->dst_port = rte_cpu_to_be_16(port);
    udp_hdr->dgram_len = rte_cpu_to_be_16(sizeof(struct rte_udp_hdr) + payload_size);
    udp_hdr->dgram_cksum = 0;
    uint16_t udp_cksum = rte_ipv4_udptcp_cksum(ipv4_hdr, (void *)udp_hdr);
    udp_hdr->dgram_cksum = rte_cpu_to_be_16(udp_cksum);

    // add the 'protocol' value to the start of the message
    *((int32_t*)ptr) = rte_cpu_to_be_32(value);

    ptr += sizeof(int32_t);
    header_size += sizeof(int32_t);

    /* set the payload */
    memset(ptr, 'a', msg_len);

    pkt->l2_len = RTE_ETHER_HDR_LEN;
    pkt->l3_len = sizeof(struct rte_ipv4_hdr);
    pkt->data_len = header_size + msg_len;
    pkt->pkt_len = header_size + msg_len;
    pkt->nb_segs = 1;

    int pkts_sent = 0;

    while(pkts_sent==0) {
        pkts_sent = rte_eth_tx_burst(1, 0, &pkt, 1);
        if(pkts_sent==0) {
            printf("failed to send packet\n");
        }
    }

//    struct rte_ether_addr tmp_mac;
//    uint16_t  tmp_port;
//    int32_t tmp_value;
//    uint32_t tmp_length;
//    int retval = receive_packet(pkt, dst_mac, &tmp_mac, &tmp_port, &tmp_value, &tmp_length);
//    printf( "PARSED port:%d value:%d msg_len: %d  retval:%d\n", tmp_port, tmp_value, tmp_length, retval);

    // note no need to free the packet, the sender will do that for us
    return 0;
}


int receive_packet(struct rte_mbuf *packet,
                   struct rte_ether_addr *my_mac,
                   struct rte_ether_addr *other_mac,
                   uint16_t *port, int32_t *value, uint32_t *msg_len) {

    uint8_t *p = rte_pktmbuf_mtod(packet, uint8_t *);
    size_t header = 0;

    // check the ethernet header
    struct rte_ether_hdr * const eth_hdr = (struct rte_ether_hdr *)(p);
    p += sizeof(*eth_hdr);
    header += sizeof(*eth_hdr);

    uint16_t eth_type = ntohs(eth_hdr->ether_type);
    if(eth_type == 35020) {
        printf("Received LLDP packet -- ignoring!\n");
        return -1;
    } else if (RTE_ETHER_TYPE_IPV4 != eth_type) {
        printf("Bad ether type: %d\n", eth_type);
        return -1;
    }

    if (!rte_is_same_ether_addr(my_mac, &eth_hdr->dst_addr) ) {
        printf("unexpected destination MAC:");
        print_mac(eth_hdr->dst_addr.addr_bytes);
        printf(" expected my MAC:");
        print_mac((uint8_t*) my_mac);
        printf("\n");
        return -1;
    }

    // save the source address
    rte_ether_addr_copy(&eth_hdr->src_addr, other_mac);
    printf("Received from MAC:");
    print_mac(other_mac->addr_bytes);
    printf("\n");

    // check the IP header
    struct rte_ipv4_hdr *const ip_hdr = (struct rte_ipv4_hdr *)(p);
    p += sizeof(*ip_hdr);
    header += sizeof(*ip_hdr);

    if (IPPROTO_UDP != ip_hdr->next_proto_id) {
        printf("Bad next proto_id:%d expected:%d\n", ip_hdr->next_proto_id, IPPROTO_UDP);
        return -1;
    }

    // check udp header
    struct rte_udp_hdr *const udp_hdr = (struct rte_udp_hdr *)(p);
    p += sizeof(*udp_hdr);
    header += sizeof(*udp_hdr);

    uint16_t dgram_len = rte_be_to_cpu_16(udp_hdr->dgram_len);

    *port = rte_be_to_cpu_16(udp_hdr->src_port);
    *value = rte_be_to_cpu_32(*((int*)p));
    *msg_len = dgram_len - sizeof(*udp_hdr) - sizeof(int32_t);

    printf( "RECEIVED port:%d value:%d msg_len: %d\n", *port, *value, *msg_len);
    return 0;
}


// initialize dpdk
int port_init(uint16_t port, struct rte_mempool *mbuf_pool, struct rte_ether_addr *my_mac) {
    struct rte_eth_conf port_conf;
    const uint16_t rx_rings = 1, tx_rings = 1;
    uint16_t nb_rxd = RX_RING_SIZE;
    uint16_t nb_txd = TX_RING_SIZE;
    int retval;
    uint16_t q;
    struct rte_eth_dev_info dev_info;
    struct rte_eth_txconf txconf;

    if (!rte_eth_dev_is_valid_port(port)) return -1;

    memset(&port_conf, 0, sizeof(struct rte_eth_conf));

    retval = rte_eth_dev_info_get(port, &dev_info);
    if (retval != 0)
    {
        printf("Error during getting device (port %u) info: %s\n", port, strerror(-retval));
        return retval;
    }

    if (dev_info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE) {
        port_conf.txmode.offloads |= RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE;
    }

    /* Configure the Ethernet device. */
    retval = rte_eth_dev_configure(port, rx_rings, tx_rings, &port_conf);
    if (retval != 0) return retval;

    retval = rte_eth_dev_adjust_nb_rx_tx_desc(port, &nb_rxd, &nb_txd);
    if (retval != 0) return retval;

    /* Allocate and set up 1 RX queue per Ethernet port. */
    for (q = 0; q < rx_rings; q++) {
        retval = rte_eth_rx_queue_setup(port, q, nb_rxd, rte_eth_dev_socket_id(port), NULL, mbuf_pool);
        if (retval < 0) return retval;
    }

    txconf = dev_info.default_txconf;
    txconf.offloads = port_conf.txmode.offloads;
    /* Allocate and set up 1 TX queue per Ethernet port. */
    for (q = 0; q < tx_rings; q++) {
        retval = rte_eth_tx_queue_setup(port, q, nb_txd, rte_eth_dev_socket_id(port), &txconf);
        if (retval < 0) return retval;
    }

    /* Starting Ethernet port. 8< */
    retval = rte_eth_dev_start(port);
    /* >8 End of starting of ethernet port. */
    if (retval < 0) return retval;

    /* Display the port MAC address. */
    retval = rte_eth_macaddr_get(port, my_mac);
    if (retval != 0) return retval;

    printf("Port %u MAC: ", port);
    print_mac(my_mac->addr_bytes);
    printf("\n");

    /* Enable RX in promiscuous mode for the Ethernet device. */
    retval = rte_eth_promiscuous_enable(port);
    if (retval != 0) return retval;

    /* End of setting RX port in promiscuous mode. */
    return 0;
}

