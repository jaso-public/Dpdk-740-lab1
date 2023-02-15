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


#define RX_RING_SIZE 1024
#define TX_RING_SIZE 1024

#define NUM_MBUFS 8191
#define MBUF_CACHE_SIZE 250
#define BURST_SIZE 32
uint32_t NUM_PING = 100;



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




struct flow {
    int last_ack;
    int next_packet;
    int num_to_send;
    uint64_t last_time;
};
typedef struct flow flow_t;

#define MAX_FLOWS 8
flow_t flows[MAX_FLOWS];
int num_flows = 1;
uint64_t timeout = 100000000; // 100 milliseconds
int window_size = 10;  // number of outstanding unacked packets.




/**
 * checks to see if all the flows have been acknowledged by the server.
 * @return 1 (true) if done, 0 (false) otherwise
 */
int is_done() {
    for(int i=0; i<num_flows; i++) {
        if(flows[i].last_ack == flows[i].num_to_send) return 0;
    }
    return 1;
}

int send_packet_to_flow(int flow) {
    if(flows[flow].next_packet == flows[flow].num_to_send) return 0;

    int next = flows[flow].next_packet++;
    return send_packet(mbuf_pool, &my_mac, &dst_mac, 5000+flow, next, message_size);
}


/**
 * resends packets on any flow where the server hasn't talked to us for a long time
 */
int resend() {
    uint64_t now = raw_time();
    for(int i=0; i<num_flows; i++) {
        if(flows[i].last_ack == flows[i].num_to_send) continue;
        uint64_t elapsed = now - flows[i].last_time;
        if(elapsed < timeout) continue;

        flows[i].next_packet = flows[i].last_ack+1;
        flows[i].last_time = raw_time();;
        int retval = send_packet_to_flow(i);
        if(retval) return retval;
    }
    return 0;
}

int send_window(int flow) {
    while(flows[flow].last_ack + window_size <= flows[flow].next_packet) {
        int retval = send_packet_to_flow(flow);
        if(retval) return retval;
    }
    flows[flow].last_time = raw_time();
    return 0;
}

int start_sending() {
    for(int i=0 ;i<num_flows; i++) {
        int retval = send_window(i);
        if(retval) return retval;
    }
    return 0;
}

int loop() {
}

void reset_server() {
    struct rte_mbuf *packets[1];
    struct rte_ether_addr other_mac;
    uint16_t flow;
    uint32_t value;
    uint32_t msg_len;

    uint64_t last = 0;
    while(1) {
        uint64_t now = raw_time();
        if(now - BILLION > last) {
            printf("Sending request to server to reset the flows.\n");
            last = now;
            int retval = send_packet(mbuf_pool, &my_mac, &dst_mac, 4000, 0, 0);
            if(retval!=0) {
                printf("Could send packet to reset the server -- exiting.\n");
                exit(-1);
            }
        }

        int nb_rx = rte_eth_rx_burst(1, 0, packets, 1);
        if (nb_rx == 0) continue;

        int retval = receive_packet(packets[0], &my_mac, &other_mac, &flow, &value, &msg_len);
        if(retval!=0) {
            printf("could receive ack packet from server -- exiting.\n");
            exit(-1);
        }

        if(flow==4000) {
            printf("Server acked our desire to reset the flows.\n");
            break;
        }
    }
}

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


static int lcore_main() {
    struct rte_mbuf *packets[BURST_SIZE];

    /*
     * reset the server so that it expects all the packets
     * it receives to start from sequence number 1.  Without
     * this reset, the server will be expecting sequence numbers
     * for the flow from whereever the last experiment stopped.
     */
    reset_server();

    /*
     * initiate the first packets for each flow.  Start by
     * filling the window for each of the flows.  We will
     * then enter the loop to deal with acknowledgements coming
     * back from the server.
     */
    start_sending();
    while(!is_done()) {
        //read packets
        int nb_rx = rte_eth_rx_burst(1, 0, packets, BURST_SIZE);
        if (nb_rx == 0) {
            // there weren't any packets received so let's see if any flows
            // timed out and retransmit if they did.
            int retval = resend();
            if (retval) return retval;
            continue;
        }

        // we received some ack packets from the server.
        for(int i=0; i<nb_rx; i++) {
            struct rte_ether_addr other_mac;
            uint16_t flow;
            uint32_t value;
            uint32_t msg_len;

            int retval = receive_packet(packets[i], &my_mac, &other_mac, &flow, &value, &msg_len);
            rte_pktmbuf_free(packets[i]);
            if (retval) continue;  // skip this packet

            if (value < 0) {
                // the server sent us a NAK, indicating the last packet it received.
                flows[flow].last_ack = -value;
                flows[flow].next_packet = flows[flow].last_ack+1;
                flows[flow].last_time = raw_time();;
                return send_packet_to_flow(flow);
            } else {
                flows[flow].last_ack = value;
                send_window(flow);
            }
        }
    }

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
