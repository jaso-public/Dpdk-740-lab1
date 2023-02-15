/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2015 Intel Corporation
 */

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

#include "../Common/common.h"

// #define PKT_TX_IPV4          (1ULL << 55)
// #define PKT_TX_IP_CKSUM      (1ULL << 54)

#define RX_RING_SIZE 1024
#define TX_RING_SIZE 1024

#define NUM_MBUFS 8191
#define MBUF_CACHE_SIZE 250
#define BURST_SIZE 32
uint32_t NUM_PING = 100;

#define BILLION (1000000000L)

/* Define the mempool globally */
struct rte_mempool *mbuf_pool = NULL;

static size_t message_size = 1000;
static uint32_t seconds = 1;

size_t window_len = 10;

int flow_size = 10000;
int packet_len = 1000;
int flow_num = 1;

// Specify the mac addresses we are going to use.
struct rte_ether_addr my_mac;
struct rte_ether_addr dst_mac = {{0xec,0xb1,0xd7,0x85,0x1a,0x13}};


static uint64_t raw_time(void) {
    struct timespec tstart;
    clock_gettime(CLOCK_MONOTONIC, &tstart);
    return ((uint64_t)tstart.tv_sec)*BILLION + ((uint64_t)tstart.tv_nsec);
}

static uint64_t time_now(uint64_t offset) {
    return raw_time() - offset;
}

uint32_t wrapsum(uint32_t sum) {
    sum = ~sum & 0xFFFF;
    return htons(sum);
}


static int parse_packet(struct sockaddr_in *src,
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
        printf("Bad next proto_id:%d expected:%d\n", ip_hdr->next_proto_id, IPPROTO_UDP);
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
/* basicfwd.c: Basic DPDK skeleton forwarding example. */

/*
 * Initializes a given port using global settings and with the RX buffers
 * coming from the mbuf_pool passed as a parameter.
 */

/* Main functional part of port initialization. 8< */
static inline int
port_init(uint16_t port, struct rte_mempool *mbuf_pool)
{
    struct rte_eth_conf port_conf;
    const uint16_t rx_rings = 1, tx_rings = 1;
    uint16_t nb_rxd = RX_RING_SIZE;
    uint16_t nb_txd = TX_RING_SIZE;
    int retval;
    uint16_t q;
    struct rte_eth_dev_info dev_info;
    struct rte_eth_txconf txconf;

    if (!rte_eth_dev_is_valid_port(port))
        return -1;

    memset(&port_conf, 0, sizeof(struct rte_eth_conf));

    retval = rte_eth_dev_info_get(port, &dev_info);
    if (retval != 0) {
        printf("Error during getting device (port %u) info: %s\n", port, strerror(-retval));
        return retval;
    }

    if (dev_info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE)
        port_conf.txmode.offloads |= RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE;

    /* Configure the Ethernet device. */
    retval = rte_eth_dev_configure(port, rx_rings, tx_rings, &port_conf);
    if (retval != 0)  return retval;

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
    if (retval < 0) return retval;

    /* Display the port MAC address. */
    retval = rte_eth_macaddr_get(port, &my_mac);
    if (retval != 0) return retval;

    int this_socket_id = (int) rte_socket_id();

    printf("port: %u socket: %d-- MAC:", port, this_socket_id);
    print_mac(my_mac.addr_bytes);
    printf("\n");

    /* Enable RX in promiscuous mode for the Ethernet device. */
    retval = rte_eth_promiscuous_enable(port);
    /* End of setting RX port in promiscuous mode. */
    if (retval != 0)
        return retval;

    return 0;
}
/* >8 End of main functional part of port initialization. */


static int lcore_main()
{
    struct rte_mbuf *packets[BURST_SIZE];
    struct rte_ether_addr other_mac;
    uint16_t flow;
    uint32_t value;
    uint32_t msg_len;


    uint64_t last = 0;
    while(1) {
        uint64_t now = raw_time();
        if(now - BILLION > last) {
            printf("sending request to server to reset the flows\n");
            last = now;
            int retval = send_packet(mbuf_pool, &my_mac, &dst_mac, 4000, 0, 0);
            if(retval!=0) {
                printf("could send packet to reset the server\n");
                exit(-1);
            }
        }

        int nb_rx = rte_eth_rx_burst(1, 0, packets, 1);
        if (nb_rx == 0) continue;

        int retval = receive_packet(packets[0], &my_mac, &other_mac, &flow, &value, &msg_len);
        if(retval!=0) {
            printf("could receive ack packet from server\n");
            exit(-1);
        }

        if(flow==4000) {
            printf("server acked our desire to reset the flows.\n");
            break;
        }
    }


    struct sliding_hdr *sld_h_ack;
    uint16_t nb_rx;
    uint64_t reqs = 0;
    uint64_t intersend_time = 0;
    // uint64_t cycle_wait = intersend_time * rte_get_timer_hz() / (1e9);

    // TODO: add in scaffolding for timing/printing out quick statistics
    int outstanding[flow_num];
    uint16_t seq[flow_num];
    size_t port_id = 0;
    for(size_t i = 0; i < flow_num; i++)
    {
        outstanding[i] = 0;
        seq[i] = 0;
    }

    while (seq[port_id] < NUM_PING) {

        send_packet(mbuf_pool, &my_mac, &dst_mac, 5001+port_id, seq[flow_num], 1000);

        // send a packet
        seq[port_id]++;
        outstanding[port_id] ++;

        uint64_t last_sent = rte_get_timer_cycles();
        printf("Sent packet at %u, %d is outstanding, intersend is %u\n", (unsigned)last_sent, outstanding[port_id], (unsigned)intersend_time);

        /* now poll on receiving packets */
        nb_rx = 0;
        reqs += 1;
        while ((outstanding[port_id] > 0)) {
            nb_rx = rte_eth_rx_burst(1, 0, packets, BURST_SIZE);
            if (nb_rx == 0) {
                continue;
            }

            printf("Received burst of %u\n", (unsigned)nb_rx);
            for (int i = 0; i < nb_rx; i++) {
                struct sockaddr_in src, dst;
                void *payload = NULL;
                size_t payload_length = 0;
                int p = parse_packet(&src, &dst, &payload, &payload_length, packets[i]);
                if (p != 0) {
                    rte_pktmbuf_free(packets[i]);
                    outstanding[p-1]--;
                } else {
                    rte_pktmbuf_free(packets[i]);
                }
            }
        }

        // port_id = (port_id+1) % flow_num;
    }
    printf("Sent %"PRIu64" packets.\n", reqs);
    // dump_latencies(&latency_dist);
    fprintf(stderr, "returning from lcore_main()\n");
    return 0;
}
/*
 * The main function, which does initialization and calls the per-lcore
 * functions.
 */

int main(int argc, char *argv[])
{

    unsigned nb_ports;
    uint16_t portid;

    if (argc == 3) {
        flow_num = (int) atoi(argv[1]);
        flow_size =  (int) atoi(argv[2]);
    } else {
        printf( "usage: ./lab1-client <flow_num> <flow_size>\n");
        return 1;
    }

    NUM_PING = flow_size / packet_len;

    /* Initializion the Environment Abstraction Layer (EAL). 8< */
    int ret = rte_eal_init(argc, argv);
    if (ret < 0) rte_exit(EXIT_FAILURE, "Error with EAL initialization\n");

    /* >8 End of initialization the Environment Abstraction Layer (EAL). */

    argc -= ret;
    argv += ret;

    nb_ports = rte_eth_dev_count_avail();
    /* Allocates mempool to hold the mbufs. 8< */
    mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL", NUM_MBUFS * nb_ports, MBUF_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
    /* >8 End of allocating mempool to hold mbuf. */

    if (mbuf_pool == NULL) rte_exit(EXIT_FAILURE, "Cannot create mbuf pool\n");

    /* Initializing all ports. 8< */
    RTE_ETH_FOREACH_DEV(portid)
    if (portid == 1 && port_init(portid, mbuf_pool) != 0)
        rte_exit(EXIT_FAILURE, "Cannot init port %" PRIu16 "\n", portid);
    /* >8 End of initializing all ports. */

    if (rte_lcore_count() > 1)
        printf("\nWARNING: Too many lcores enabled. Only 1 used.\n");

    /* Call lcore_main on the main core only. Called on single lcore. 8< */
    lcore_main();
    /* >8 End of called on single lcore. */

    fprintf(stderr, "Done!\n");
    /* clean up the EAL */
    rte_eal_cleanup();

    return 0;
}
