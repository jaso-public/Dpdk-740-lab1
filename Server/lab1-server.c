/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2015 Intel Corporation
 */

#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdio.h>
#include <inttypes.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_cycles.h>
#include <rte_lcore.h>
#include <rte_mbuf.h>


#include "../Common/common.h"


#define RX_RING_SIZE 1024
#define TX_RING_SIZE 1024

#define NUM_MBUFS 8191
#define MBUF_CACHE_SIZE 250
#define BURST_SIZE 32
#define PORT_NUM 4

struct rte_mempool *mbuf_pool = NULL;
static struct rte_ether_addr my_mac;
size_t window_len = 10;

int flow_size = 10000;
int packet_len = 1000;
int ack_len = 10;
int flow_num = 1;


/*
 * Initializes a given port using global settings and with the RX buffers
 * coming from the mbuf_pool passed as a parameter.
 */

/* Main functional part of port initialization. 8< */
static int port_init(uint16_t port, struct rte_mempool *mbuf_pool) {
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
    retval = rte_eth_macaddr_get(port, &my_mac);
    if (retval != 0) return retval;

    printf("Port %u MAC: ", port);
    print_mac(my_mac.addr_bytes);
    printf("\n");

    /* Enable RX in promiscuous mode for the Ethernet device. */
    retval = rte_eth_promiscuous_enable(port);
    if (retval != 0) return retval;

    /* End of setting RX port in promiscuous mode. */
    return 0;
}
/* >8 End of main functional part of port initialization. */

static int get_port(struct sockaddr_in *src,
                        struct sockaddr_in *dst,
                        void **payload,
                        size_t *payload_len,
                        struct rte_mbuf *pkt)
{
    // packet layout order is (from outside -> in):
    // ether_hdr
    // ipv4_hdr
    // udp_hdr
    // client timestamp
    uint8_t *p = rte_pktmbuf_mtod(pkt, uint8_t *);
    size_t header = 0;

    // check the ethernet header
    struct rte_ether_hdr * const eth_hdr = (struct rte_ether_hdr *)(p);
    p += sizeof(*eth_hdr);
    header += sizeof(*eth_hdr);
    uint16_t eth_type = ntohs(eth_hdr->ether_type);

    if(eth_type == 35020) {
	    printf("Received LLDP packet -- ignoring!\n");
	    return 0;
    } else if (RTE_ETHER_TYPE_IPV4 != eth_type) {
        printf("Bad ether type: %d\n", eth_type);
        return 0;
    }

    if (!rte_is_same_ether_addr(&my_mac, &eth_hdr->dst_addr) ) {
        printf("unexpected MAC:");
        print_mac(eth_hdr->dst_addr.addr_bytes);
        printf("\n");
        return 0;
    }

    // check the IP header
    struct rte_ipv4_hdr *const ip_hdr = (struct rte_ipv4_hdr *)(p);
    p += sizeof(*ip_hdr);
    header += sizeof(*ip_hdr);

    // In network byte order.
    in_addr_t ipv4_src_addr = ip_hdr->src_addr;
    in_addr_t ipv4_dst_addr = ip_hdr->dst_addr;

    if (IPPROTO_UDP != ip_hdr->next_proto_id) {
        printf("Bad next proto_id: %d\n", ip_hdr->next_proto_id);
        return 0;
    }
    
    src->sin_addr.s_addr = ipv4_src_addr;
    dst->sin_addr.s_addr = ipv4_dst_addr;

    // check udp header
    struct rte_udp_hdr * const udp_hdr = (struct rte_udp_hdr *)(p);
    p += sizeof(*udp_hdr);
    header += sizeof(*udp_hdr);

    // In network byte order.
    in_port_t udp_src_port = udp_hdr->src_port;
    in_port_t udp_dst_port = udp_hdr->dst_port;
    int ret = 0;

    uint16_t p1 = rte_cpu_to_be_16(5001);
    uint16_t p2 = rte_cpu_to_be_16(5002);
    uint16_t p3 = rte_cpu_to_be_16(5003);
    uint16_t p4 = rte_cpu_to_be_16(5004);
    // printf("dst port %d, %d\n", udp_hdr->dst_port, p2);
    
    if (udp_hdr->dst_port ==  p1)
    {
        ret = 1;
    }
    if (udp_hdr->dst_port ==  p2)
    {
        ret = 2;
    }
    if (udp_hdr->dst_port ==  p3)
    {
        ret = 3;
    }
    if (udp_hdr->dst_port ==  p4)
    {
        ret = 4;
    }

    src->sin_port = udp_src_port;
    dst->sin_port = udp_dst_port;
    
    src->sin_family = AF_INET;
    dst->sin_family = AF_INET;
    
    *payload_len = pkt->pkt_len - header;
    *payload = (void *)p;
    
    return ret;

}

int flow_acks[8];

/* Basic forwarding application lcore. 8< */
static int lcore_main(void) {
    uint16_t port;
    uint32_t rec = 0;
    uint16_t nb_rx;

    /*
     * Check that the port is on the same NUMA node as the polling thread
     * for best performance.
     */
    RTE_ETH_FOREACH_DEV(port) {
        int port_socket_id = rte_eth_dev_socket_id(port);
        int this_socket_id = (int) rte_socket_id();
        if (port_socket_id >= 0 && port_socket_id != this_socket_id) {
            printf("WARNING: port %u is on remote NUMA node to polling thread.\n", port);
            printf("         polling thread socket_id:%d -- port socket_id:%d\n", this_socket_id, port_socket_id);
            printf("         *** Performance will not be optimal. ***\n");
        }
    }

    printf("\nCore %u forwarding packets. [Ctrl+C to quit]\n", rte_lcore_id());

    /* Main work of application loop. 8< */
    for (;;) {
       struct rte_mbuf *bufs[BURST_SIZE];

        const uint16_t nb_rx = rte_eth_rx_burst(1, 0, bufs, BURST_SIZE);

        if (unlikely(nb_rx == 0)) continue;

        for (int i = 0; i < nb_rx; i++) {
            struct rte_ether_addr other_mac;
            uint16_t flow;
            uint32_t value;
            uint32_t msg_len;

            int retval = receive_packet(bufs[i], &my_mac, &other_mac, &flow, &value, &msg_len);
            rte_pktmbuf_free(bufs[i]);
            if (retval != 0) continue;
            printf("received flow:%d value:%d msg_len:%d\n", flow, value, msg_len);

            if (flow == 4000) {
                // magic value that resets all the flows
                for (int j = 0; j < 8; j++) {
                    flow_acks[j] = 0;
                }

                // send a packet back to the sender acknowledging that we reset the flows.
                retval = send_packet(mbuf_pool, &my_mac, &other_mac, flow, 0, 0);
                if (retval != 0) {
                    printf("error acknowledging reset\n");
                    exit(-1);
                }
                printf("All flows have been reset!\n");
                continue;
            }

            if (flow < 5000 || flow >= 5008) {
                printf("received a packet on an unexpected port:%d\n", port);
                continue;
            }
            flow_num = flow - 5000;
            int response = value;

            // did we get the packet we expected?
            if (value - 1 == flow_acks[flow_num]) {
                flow_acks[flow_num] = value;
            } else {
                response = -flow_acks[flow_num];
            }

            retval = send_packet(mbuf_pool, &my_mac, &other_mac, flow, response, 0);
            if (retval != 0) {
                printf("error sending\n");
                exit(-1);
            }
        }
    }
}

/*
 * The main function, which does initialization and calls the per-lcore
 * functions.
 */
int main(int argc, char *argv[])
{
    // struct rte_mempool *mbuf_pool;
    unsigned nb_ports = 1;
    uint16_t portid;
    
    /* Initializion the Environment Abstraction Layer (EAL). 8< */

    int ret = rte_eal_init(argc, argv);
    if (ret < 0) rte_exit(EXIT_FAILURE, "Error with EAL initialization\n");

    /* >8 End of initialization the Environment Abstraction Layer (EAL). */

    argc -= ret;
    argv += ret;

    nb_ports = rte_eth_dev_count_avail();
    /* Allocates mempool to hold the mbufs. 8< */
    mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL", NUM_MBUFS * nb_ports,
                                        MBUF_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
    /* >8 End of allocating mempool to hold mbuf. */

    if (mbuf_pool == NULL)
        rte_exit(EXIT_FAILURE, "Cannot create mbuf pool\n");

    /* Initializing all ports. 8< */
    RTE_ETH_FOREACH_DEV(portid)
    if (portid == 1 && port_init(portid, mbuf_pool) != 0) {
        rte_exit(EXIT_FAILURE, "Cannot init port %" PRIu16 "\n", portid);
    }

    int core_count = rte_lcore_count();
    if (core_count > 1) {
        printf("\nWARNING: Too many lcores enabled. Only 1 used.  core_count:%d\n", core_count);
    }

    /* Call lcore_main on the main core only. Called on single lcore. 8< */
    lcore_main();

    rte_eal_cleanup();
    return 0;
}
