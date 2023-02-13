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

#define RX_RING_SIZE 1024
#define TX_RING_SIZE 1024

#define NUM_MBUFS 8191
#define MBUF_CACHE_SIZE 250
#define BURST_SIZE 32
#define PORT_NUM 4

struct rte_mempool *mbuf_pool = NULL;
static struct rte_ether_addr my_eth;
size_t window_len = 10;

int flow_size = 10000;
int packet_len = 1000;
int ack_len = 10;
int flow_num = 1;

uint32_t
checksum(unsigned char *buf, uint32_t nbytes, uint32_t sum)
{
	unsigned int	 i;

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

	return sum;
}

uint32_t
wrapsum(uint32_t sum)
{
	sum = ~sum & 0xFFFF;
	return htons(sum);
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
	if (retval != 0)
	{
		printf("Error during getting device (port %u) info: %s\n",
			   port, strerror(-retval));
		return retval;
	}

	if (dev_info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE)
		port_conf.txmode.offloads |=
			RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE;

	/* Configure the Ethernet device. */
	retval = rte_eth_dev_configure(port, rx_rings, tx_rings, &port_conf);
	if (retval != 0)
		return retval;

	retval = rte_eth_dev_adjust_nb_rx_tx_desc(port, &nb_rxd, &nb_txd);
	if (retval != 0)
		return retval;

	/* Allocate and set up 1 RX queue per Ethernet port. */
	for (q = 0; q < rx_rings; q++)
	{
		retval = rte_eth_rx_queue_setup(port, q, nb_rxd,
										rte_eth_dev_socket_id(port), NULL, mbuf_pool);
		if (retval < 0)
			return retval;
	}

	txconf = dev_info.default_txconf;
	txconf.offloads = port_conf.txmode.offloads;
	/* Allocate and set up 1 TX queue per Ethernet port. */
	for (q = 0; q < tx_rings; q++)
	{
		retval = rte_eth_tx_queue_setup(port, q, nb_txd,
										rte_eth_dev_socket_id(port), &txconf);
		if (retval < 0)
			return retval;
	}

	/* Starting Ethernet port. 8< */
	retval = rte_eth_dev_start(port);
	/* >8 End of starting of ethernet port. */
	if (retval < 0)
		return retval;

	/* Display the port MAC address. */
	retval = rte_eth_macaddr_get(port, &my_eth);
	if (retval != 0)
		return retval;

	printf("Port %u MAC: %02" PRIx8 " %02" PRIx8 " %02" PRIx8
		   " %02" PRIx8 " %02" PRIx8 " %02" PRIx8 "\n",
		   port, RTE_ETHER_ADDR_BYTES(&my_eth));

	/* Enable RX in promiscuous mode for the Ethernet device. */
	retval = rte_eth_promiscuous_enable(port);
	/* End of setting RX port in promiscuous mode. */
	if (retval != 0)
		return retval;

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
    struct rte_ether_addr mac_addr = {};
	rte_eth_macaddr_get(1, &mac_addr);
    if (!rte_is_same_ether_addr(&mac_addr, &eth_hdr->dst_addr) ) {
        printf("Bad MAC: %02" PRIx8 " %02" PRIx8 " %02" PRIx8
			   " %02" PRIx8 " %02" PRIx8 " %02" PRIx8 "\n",
            eth_hdr->dst_addr.addr_bytes[0], eth_hdr->dst_addr.addr_bytes[1],
			eth_hdr->dst_addr.addr_bytes[2], eth_hdr->dst_addr.addr_bytes[3],
			eth_hdr->dst_addr.addr_bytes[4], eth_hdr->dst_addr.addr_bytes[5]);
        return 0;
    }
    if (RTE_ETHER_TYPE_IPV4 != eth_type) {
        printf("Bad ether type\n");
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
        printf("Bad next proto_id\n");
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

/* Basic forwarding application lcore. 8< */
static __rte_noreturn void
lcore_main(void)
{
	uint16_t port;
	uint32_t rec = 0;
	uint16_t nb_rx;

	/*
	 * Check that the port is on the same NUMA node as the polling thread
	 * for best performance.
	 */
	RTE_ETH_FOREACH_DEV(port)
	if (rte_eth_dev_socket_id(port) >= 0 &&
		rte_eth_dev_socket_id(port) !=
			(int)rte_socket_id())
		printf("WARNING, port %u is on remote NUMA node to "
			   "polling thread.\n\tPerformance will "
			   "not be optimal.\n",
			   port);

	printf("\nCore %u forwarding packets. [Ctrl+C to quit]\n",
		   rte_lcore_id());

	/* Main work of application loop. 8< */
	for (;;)
	{
		RTE_ETH_FOREACH_DEV(port)
		{
			/* Get burst of RX packets, from port1 */
			if (port != 1)
				continue;

			struct rte_mbuf *bufs[BURST_SIZE];
			struct rte_mbuf *pkt;
			struct rte_ether_hdr *eth_h;
			struct rte_ipv4_hdr *ip_h;
			struct rte_udp_hdr *udp_h;
			struct rte_ether_addr eth_addr;
			uint32_t ip_addr;
			uint8_t i;
			uint8_t nb_replies = 0;

			struct rte_mbuf *acks[BURST_SIZE];
			struct rte_mbuf *ack;
			// char *buf_ptr;
			struct rte_ether_hdr *eth_h_ack;
			struct rte_ipv4_hdr *ip_h_ack;
			struct rte_udp_hdr *udp_h_ack;

			const uint16_t nb_rx = rte_eth_rx_burst(port, 0, bufs, BURST_SIZE);

			if (unlikely(nb_rx == 0))
				continue;

			for (i = 0; i < nb_rx; i++)
			{
				pkt = bufs[i];
				struct sockaddr_in src, dst;
                void *payload = NULL;
                size_t payload_length = 0;
                int udp_port_id = get_port(&src, &dst, &payload, &payload_length, pkt);
				if(udp_port_id != 0){
					printf("received: %d\n", rec);
				}

				eth_h = rte_pktmbuf_mtod(pkt, struct rte_ether_hdr *);
				if (eth_h->ether_type != rte_be_to_cpu_16(RTE_ETHER_TYPE_IPV4))
				{
					rte_pktmbuf_free(pkt);
					continue;
				}

				ip_h = rte_pktmbuf_mtod_offset(pkt, struct rte_ipv4_hdr *,
											   sizeof(struct rte_ether_hdr));

				udp_h = rte_pktmbuf_mtod_offset(pkt, struct rte_udp_hdr *,
											   sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr) );
				// rte_pktmbuf_dump(stdout, pkt, pkt->pkt_len);
				rec++;


				// Construct and send Acks
				ack = rte_pktmbuf_alloc(mbuf_pool);
				if (ack == NULL) {
					printf("Error allocating tx mbuf\n");
					return -EINVAL;
				}
				size_t header_size = 0;

				uint8_t *ptr = rte_pktmbuf_mtod(ack, uint8_t *);
				/* add in an ethernet header */
				eth_h_ack = (struct rte_ether_hdr *)ptr;
				
				rte_ether_addr_copy(&my_eth, &eth_h_ack->src_addr);
				rte_ether_addr_copy(&eth_h->src_addr, &eth_h_ack->dst_addr);
				eth_h_ack->ether_type = rte_be_to_cpu_16(RTE_ETHER_TYPE_IPV4);
				ptr += sizeof(*eth_h_ack);
				header_size += sizeof(*eth_h_ack);

				/* add in ipv4 header*/
				ip_h_ack = (struct rte_ipv4_hdr *)ptr;
				ip_h_ack->version_ihl = 0x45;
				ip_h_ack->type_of_service = 0x0;
				ip_h_ack->total_length = rte_cpu_to_be_16(sizeof(struct rte_ipv4_hdr) + sizeof(struct rte_udp_hdr) + ack_len);
				ip_h_ack->packet_id = rte_cpu_to_be_16(1);
				ip_h_ack->fragment_offset = 0;
				ip_h_ack->time_to_live = 64;
				ip_h_ack->next_proto_id = IPPROTO_UDP;
				ip_h_ack->src_addr = ip_h->dst_addr;
				ip_h_ack->dst_addr = ip_h->src_addr;

				uint32_t ipv4_checksum = wrapsum(checksum((unsigned char *)ip_h_ack, sizeof(struct rte_ipv4_hdr), 0));
				ip_h_ack->hdr_checksum = rte_cpu_to_be_32(ipv4_checksum);
				header_size += sizeof(*ip_h_ack);
				ptr += sizeof(*ip_h_ack);
				/* add in UDP hdr*/
				udp_h_ack = (struct rte_udp_hdr *)ptr;
				udp_h_ack->src_port = udp_h->dst_port;
				udp_h_ack->dst_port = udp_h->src_port;
				udp_h_ack->dgram_len = rte_cpu_to_be_16(sizeof(struct rte_udp_hdr)+ack_len);

				uint16_t udp_cksum =  rte_ipv4_udptcp_cksum(ip_h_ack, (void *)udp_h_ack);

				// printf("Udp checksum is %u\n", (unsigned)udp_cksum);
				udp_h_ack->dgram_cksum = rte_cpu_to_be_16(udp_cksum);
				
				/* set the payload */
				memset(ptr, 'a', ack_len);

				ack->l2_len = RTE_ETHER_HDR_LEN;
				ack->l3_len = sizeof(struct rte_ipv4_hdr);
				// pkt->ol_flags = PKT_TX_IP_CKSUM | PKT_TX_IPV4;
				ack->data_len = header_size + ack_len;
				ack->pkt_len = header_size + ack_len;
				ack->nb_segs = 1;
				int pkts_sent = 0;

				unsigned char *ack_buffer = rte_pktmbuf_mtod(ack, unsigned char *);
				acks[nb_replies++] = ack;
				
				rte_pktmbuf_free(bufs[i]);

			}

			/* Send back echo replies. */
			uint16_t nb_tx = 0;
			if (nb_replies > 0)
			{
				nb_tx = rte_eth_tx_burst(port, 0, acks, nb_replies);
			}

			/* Free any unsent packets. */
			if (unlikely(nb_tx < nb_rx))
			{
				uint16_t buf;
				for (buf = nb_tx; buf < nb_rx; buf++)
					rte_pktmbuf_free(acks[buf]);
			}
		}
	}
	/* >8 End of loop. */
}
/* >8 End Basic forwarding application lcore. */

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
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Error with EAL initialization\n");
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
	if (portid == 1 && port_init(portid, mbuf_pool) != 0)
		rte_exit(EXIT_FAILURE, "Cannot init port %" PRIu16 "\n",
				 portid);
	/* >8 End of initializing all ports. */

	if (rte_lcore_count() > 1)
		printf("\nWARNING: Too many lcores enabled. Only 1 used.\n");

	/* Call lcore_main on the main core only. Called on single lcore. 8< */
	lcore_main();
	/* >8 End of called on single lcore. */

	/* clean up the EAL */
	rte_eal_cleanup();

	return 0;
}
