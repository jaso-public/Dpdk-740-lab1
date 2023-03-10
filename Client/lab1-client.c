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


#define NUM_MBUFS 8191
#define MBUF_CACHE_SIZE 250
#define BURST_SIZE 32




/* Define the mempool globally */
struct rte_mempool *mbuf_pool = NULL;

// how big is each packet.
int message_size = 1476;

// how many outstanding unacked packets can there be for each flow.
int window_size = 16;

// how many simultaneous flows are there
int num_flows = 1;

// the number of packets to send for each flow.
int num_to_send = 100;


// Specify the mac addresses we are going to use.
struct rte_ether_addr my_mac;
//struct rte_ether_addr dst_mac = {{0xec,0xb1,0xd7,0x85,0x1a,0x13}};
struct rte_ether_addr dst_mac = {{0x14,0x58,0xd0,0x58,0xef,0xb3}};


struct flow {
    int last_ack;
    int next_packet;
    int num_to_send;
    uint64_t last_time;
};


#define MAX_FLOWS 8
struct flow flows[MAX_FLOWS];


uint64_t timeout = 100000000; // 100 milliseconds





/**
 * checks to see if all the flows have been acknowledged by the server.
 * @return 1 (true) if done, 0 (false) otherwise
 */
int is_done() {
    for(int i=0; i<num_flows; i++) {
        if(flows[i].last_ack < flows[i].num_to_send) return 0;
    }
    return 1;
}

int send_packet_to_flow(int flow) {
//    printf("send_packet_to_flow  flow:%d last_ack:%d next_packet:%d, num_to_send:%d, last_time:%lu\n",
//           flow, flows[flow].last_ack, flows[flow].next_packet, flows[flow].num_to_send, flows[flow].last_time);

    if(flows[flow].next_packet > flows[flow].num_to_send) return 0;

    int next = flows[flow].next_packet++;
    int retval = send_packet(mbuf_pool, &my_mac, &dst_mac, 5000+flow, next, message_size);
     return retval;
}


/**
 * resends packets on any flow where the server hasn't talked to us for a long time
 */
int resend() {
    uint64_t now = raw_time();
    for(int i=0; i<num_flows; i++) {
        if(flows[i].last_ack >= flows[i].num_to_send) continue;
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
    if(flows[flow].last_ack >= flows[flow].num_to_send) return 0;

    while(1) {
        if(flows[flow].next_packet > flows[flow].last_ack + window_size) return 0;
        if(flows[flow].next_packet > flows[flow].num_to_send) return 0;
        int retval = send_packet_to_flow(flow);
        if(retval) return retval;
    }
}

int start_sending() {
    printf("start sending num_flows:%d\n",num_flows);

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
        rte_pktmbuf_free(packets[0]);
        if(retval!=0) continue;

        if(flow==4000) {
            printf("Server acked our desire to reset the flows.\n");
            break;
        }
    }
}


static int lcore_main() {
    struct rte_mbuf *packets[BURST_SIZE];

    /*
     * initiate the first packets for each flow.  Start by
     * filling the window for each of the flows.  We will
     * then enter the loop to deal with acknowledgements coming
     * back from the server.
     */
    start_sending();

    while(is_done() == 0) {
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

            flow = flow - 5000;
            flows[flow].last_time = raw_time();

            if (value < 0) {
                // the server sent us a NAK, indicating the last packet it received.
                flows[flow].last_ack = -value;
                flows[flow].next_packet = flows[flow].last_ack+1;
                return send_packet_to_flow(flow);
            } else {
                flows[flow].last_ack = max(value, flows[flow].last_ack);
                if(flows[flow].next_packet <= flows[flow].last_ack) flows[flow].next_packet = flows[flow].last_ack+1;
                send_window(flow);
            }
        }
    }

    printf("returning from lcore_main()\n");
    return 0;
}
/*
 * The main function, which does initialization and calls the per-lcore
 * functions.
 */

int main(int argc, char *argv[]) {

    printf( "usage: ./lab1-client [flow_num] [flow_size] [window_size] [payload_size]\n");

    if (argc > 1) {
        num_flows = atoi(argv[1]);
    }

    int64_t flow_size = 1000000;
    if (argc > 2) {
        flow_size = atol(argv[2]);
    }

    if (argc > 3) {
        window_size = atoi(argv[3]);
    }

    if (argc > 4) {
        message_size = atoi(argv[4]);
    }

    if(num_flows <1 || num_flows>8) {
        printf("invalid number of flows(%d) must in range [1,8]\n", num_flows);
        exit(-1);
    }

    if(flow_size < 1) {
        printf("invalid flow size (%ld) must greater than zero\n", flow_size);
        exit(-1);
    }

    if(window_size <1 || window_size>128/num_flows) {
        printf("invalid window size(%d) must in range [1,%d]\n", window_size, 128/num_flows);
        exit(-1);
    }

    if(message_size <1 || message_size>1476) {
        printf("invalid message size(%d) must in range [1,1476]\n", message_size);
        exit(-1);
    }

    num_to_send = (flow_size + message_size - 1) / message_size;
    uint64_t  actual = num_to_send;
    actual *= message_size;

    printf("number of flows: %d\n", num_flows);
    printf("requested bytes per flow: %lu\n", flow_size);
    printf("actual bytes per flow: %lu\n", actual);
    printf("payload size per packet: %d\n", message_size);
    printf("number of packets per flow: %d\n", num_to_send);
    printf("window size per flow: %d\n", window_size);

    for(int i=0; i<num_flows; i++) {
        flows[i].last_ack = 0;
        flows[i].next_packet = 1;
        flows[i].num_to_send = num_to_send;
        flows[i].last_time = 0;
    }

    /* Initializion the Environment Abstraction Layer (EAL). 8< */
    int ret = rte_eal_init(argc, argv);
    if (ret < 0) rte_exit(EXIT_FAILURE, "Error with EAL initialization\n");

    /* >8 End of initialization the Environment Abstraction Layer (EAL). */

    argc -= ret;
    argv += ret;

    /* Allocates mempool to hold the mbufs. 8< */
    unsigned nb_ports = rte_eth_dev_count_avail();
    mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL", NUM_MBUFS * nb_ports, MBUF_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
    if (mbuf_pool == NULL) rte_exit(EXIT_FAILURE, "Cannot create mbuf pool\n");

    /* Initializing all ports. 8< */
    uint16_t portid;
    RTE_ETH_FOREACH_DEV(portid)
    if (portid == 1 && port_init(portid, mbuf_pool, &my_mac) != 0) {
        rte_exit(EXIT_FAILURE, "Cannot init port %" PRIu16 "\n", portid);
    }

    if (rte_lcore_count() > 1) {
        printf("\nWARNING: Too many lcores enabled. Only 1 used.\n");
    }

    /*
     * reset the server so that it expects all the packets
     * it receives to start from sequence number 1.  Without
     * this reset, the server will be expecting sequence numbers
     * for the flow from wherever the last experiment stopped.
     */
    reset_server();

    // do the transmission and get the timing
    uint64_t start = raw_time();
    lcore_main();
    uint64_t end = raw_time();

    /* clean up the EAL */
    rte_eal_cleanup();

    // report results.
    uint64_t elapsed = end - start;
    printf("Done  elapsed:%lu(ns) %lu(ms) \n", elapsed, elapsed/1000000);

    return 0;
}
