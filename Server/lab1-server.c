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


int flow_acks[8];
int flow_response[8];

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

        for(int i=0; i<8; i++) flow_response[i] = -1;

        struct rte_ether_addr other_mac;
        for (int i = 0; i < nb_rx; i++) {
            uint16_t flow;
            uint32_t value;
            uint32_t msg_len;

            int retval = receive_packet(bufs[i], &my_mac, &other_mac, &flow, &value, &msg_len);
            rte_pktmbuf_free(bufs[i]);
            if (retval != 0) continue;

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
                printf("**** All flows have been reset!\n");
                continue;
            }

            if (flow < 5000 || flow >= 5008) {
                printf("received a packet on an unexpected port:%d\n", port);
                continue;
            }
            flow_num = flow - 5000;

            // did we get the packet we expected?
            if (value - 1 == flow_acks[flow_num]) {
                // ack the next packet
                flow_acks[flow_num] = value;
                flow_response[flow_num] = value;
            } else if (value <= flow_acks[flow_num]) {
                // just ack to where we are
                flow_response[flow_num] = flow_acks[flow_num];
             } else {
                printf("Out of order: flow:%d value:%d, last_ac:%d", flow_num, value, flow_acks[flow_num]);
                flow_response[flow_num] = -flow_acks[flow_num];
            }
        }

        for(int i=0; i<8; i++) {
            if(flow_response[i] == -1) continue;
            int retval = send_packet(mbuf_pool, &my_mac, &other_mac, i+5000, flow_response[i], 0);
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
    if (portid == 1 && port_init(portid, mbuf_pool, &my_mac) != 0) {
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
