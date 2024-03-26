/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2016 Intel Corporation
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>
#include <sys/types.h>
#include <sys/queue.h>
#include <setjmp.h>
#include <stdarg.h>
#include <ctype.h>
#include <errno.h>
#include <getopt.h>
#include <signal.h>
#include <stdbool.h>

#include <rte_common.h>
#include <rte_log.h>
#include <rte_malloc.h>
#include <rte_memory.h>
#include <rte_memcpy.h>
#include <rte_eal.h>
#include <rte_launch.h>
#include <rte_cycles.h>
#include <rte_prefetch.h>
#include <rte_lcore.h>
#include <rte_per_lcore.h>
#include <rte_branch_prediction.h>
#include <rte_interrupts.h>
#include <rte_random.h>
#include <rte_debug.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>
#include <rte_string_fns.h>

#include <rte_ip.h>
#include <rte_udp.h>
#include <rte_tcp.h>
#include <rte_hash.h>
#include <rte_jhash.h>

static volatile bool force_quit;

/* MAC updating enabled by default */
static int mac_updating = 1;

/* Ports set in promiscuous mode off by default. */
static int promiscuous_on;

#define RTE_LOGTYPE_L2FWD RTE_LOGTYPE_USER1

#define MAX_PKT_BURST 32
#define BURST_TX_DRAIN_US 1 /* TX drain every ~100us */
#define MEMPOOL_CACHE_SIZE 256

/*
 * Configurable number of RX/TX ring descriptors
 */
#define RX_DESC_DEFAULT 8192
#define TX_DESC_DEFAULT 8192
static uint16_t nb_rxd = RX_DESC_DEFAULT;
static uint16_t nb_txd = TX_DESC_DEFAULT;

/* ethernet addresses of ports */
static struct rte_ether_addr l2fwd_ports_eth_addr[RTE_MAX_ETHPORTS];

/* mask of enabled ports */
static uint32_t l2fwd_enabled_port_mask = 0;

/* list of enabled ports */
static uint32_t l2fwd_dst_ports[RTE_MAX_ETHPORTS];

struct port_pair_params {
#define NUM_PORTS	2
	uint16_t port[NUM_PORTS];
} __rte_cache_aligned;

static struct port_pair_params port_pair_params_array[RTE_MAX_ETHPORTS / 2];
static struct port_pair_params *port_pair_params;
static uint16_t nb_port_pair_params;

static unsigned int l2fwd_rx_queue_per_lcore = 1;

#define MAX_RX_QUEUE_PER_LCORE 16
#define MAX_TX_QUEUE_PER_PORT 16
/* List of queues to be polled for a given lcore. 8< */
struct lcore_queue_conf {
	unsigned n_rx_port;
	unsigned rx_port_list[MAX_RX_QUEUE_PER_LCORE];
} __rte_cache_aligned;
struct lcore_queue_conf lcore_queue_conf[RTE_MAX_LCORE];
/* >8 End of list of queues to be polled for a given lcore. */

static struct rte_eth_dev_tx_buffer *tx_buffer[RTE_MAX_ETHPORTS];

static struct rte_eth_conf port_conf = {
	.rxmode = {
		.mq_mode = RTE_ETH_MQ_RX_NONE
	},
	// .rx_adv_conf = {
	// 	.rss_conf = {
	// 		.rss_key = NULL,
	// 		.rss_key_len = 40,
	// 		.rss_hf = 0,
	// 	},
	// },
	.txmode = {
		.mq_mode = RTE_ETH_MQ_TX_NONE,
	},
	
};

#define NUM_LCORES_FOR_RSS 7
#define USING_TRACE 1


// Port Knocking DS
#define MAX_IPV4_5TUPLES 1024
enum state {
  CLOSED_0 = 0,
  CLOSED_1,
  CLOSED_2,
  OPEN
};

enum port_list{
	PORT_0 = 100,
	PORT_1,
	PORT_2
};

FILE *log_file;

#define WRITE_INTO_FILE 1

// Metadata element for SCR
struct metadata_elem{
	// uint16_t ethtype;
	// uint8_t proto;
	uint32_t src_ip;
	uint16_t dst_port;
	bool tcp_syn_flag;
	bool tcp_fin_flag;
}__rte_packed;
// (Packed as this will be transfered over the network and adding padding is unecessary)
int ctr = 0;

#define NUM_PKTS_SCR NUM_LCORES_FOR_RSS

#define LATENCY_SAMPLE_SIZE 64
uint64_t tsc_process_burst_rx[NUM_LCORES_FOR_RSS][LATENCY_SAMPLE_SIZE];
uint64_t tsc_between_bursts_rx[NUM_LCORES_FOR_RSS][LATENCY_SAMPLE_SIZE];
uint64_t burst_size[NUM_LCORES_FOR_RSS][LATENCY_SAMPLE_SIZE];




/*
 * ethdev
 */
// #ifndef ETHDEV_RXQ_RSS_MAX
// #define ETHDEV_RXQ_RSS_MAX 16
// #endif

// struct ethdev_params_rss {
// 	uint32_t queue_id[ETHDEV_RXQ_RSS_MAX];
// 	uint32_t n_queues;
// };

// #define RETA_CONF_SIZE     (RTE_ETH_RSS_RETA_SIZE_512 / RTE_ETH_RETA_GROUP_SIZE)


struct rte_mempool * l2fwd_pktmbuf_pool = NULL;

/* Per-port statistics struct */
struct l2fwd_port_statistics {
	uint64_t tx;
	uint64_t prev_tx;
	uint64_t rx;
	uint64_t prev_rx;
	uint64_t dropped;
	uint64_t prev_dropped;
} __rte_cache_aligned;
struct l2fwd_port_statistics port_statistics[RTE_MAX_ETHPORTS];
struct rte_eth_stats old_eth_stats;

struct rte_hash *state_map[NUM_LCORES_FOR_RSS];


#define MAX_TIMER_PERIOD 86400 /* 1 day max */
/* A tsc-based timer responsible for triggering statistics printout */
static uint64_t timer_period = 1; /* default period is 10 seconds */

/* Print out statistics on packets dropped */
static void
print_stats(void)
{
	uint64_t total_packets_dropped, total_packets_tx, total_packets_rx, prev_total_packets_tx, prev_total_packets_rx;
	uint64_t timer_in_sec = timer_period/rte_get_timer_hz();
	struct rte_eth_stats eth_stats;
	unsigned portid;
	int ret;


	total_packets_dropped = 0;
	total_packets_tx = 0;
	total_packets_rx = 0;
	prev_total_packets_rx = 0;
	prev_total_packets_tx = 0;

	const char clr[] = { 27, '[', '2', 'J', '\0' };
	const char topLeft[] = { 27, '[', '1', ';', '1', 'H','\0' };

		/* Clear screen and move to top left */
	// printf("%s%s", clr, topLeft);

	printf("\nPort statistics ====================================");

	for (portid = 0; portid < RTE_MAX_ETHPORTS; portid++) {
		/* skip disabled ports */
		if ((l2fwd_enabled_port_mask & (1 << portid)) == 0)
			continue;
		unsigned tx = 0, rx = 0, dropped = 0, prev_tx = 0, prev_rx = 0;
		for(int i = 0; i < NUM_LCORES_FOR_RSS; i++){
			tx += port_statistics[i].tx;
			rx += port_statistics[i].rx;
			dropped += port_statistics[i].dropped;

			prev_tx = port_statistics[i].tx - port_statistics[i].prev_tx;
			port_statistics[i].prev_tx = port_statistics[i].tx;

			prev_rx = port_statistics[i].rx - port_statistics[i].prev_rx;
			port_statistics[i].prev_rx = port_statistics[i].rx;

			prev_total_packets_rx += prev_rx;
			prev_total_packets_tx += prev_tx;

			printf("\nStatistics for lcore %u ------------------------------"
			"\nTotal Packets sent: %18"PRIu64
			"\nTotal Packets received: %14"PRIu64
			"\nTotal Packets dropped: %15"PRIu64
			"\nCurrent TX rate (PPS): %15"PRIu64
			"\nCurrent RX rate (PPS): %15"PRIu64,
			i,
			port_statistics[i].tx,
			port_statistics[i].rx,
			port_statistics[i].dropped,
			(prev_tx)/ timer_in_sec,
			(prev_rx)/ timer_in_sec);
		} 
		total_packets_dropped += dropped;
		total_packets_tx += tx;
		total_packets_rx += rx;
	}
	// TODO: Update get port statistics to ensure that it
	// supports printing stats for multiple ports
	ret = rte_eth_stats_get(0, &eth_stats);
	printf("\nAggregate statistics ==============================="
		   "\nTotal packets sent: %18"PRIu64
		   "\nTotal packets received: %14"PRIu64
		   "\nTotal packets dropped: %15"PRIu64
		   "\nTotal TX rate (PPS): %17"PRIu64
		   "\nTotal RX rate (PPS): %17"PRIu64
		   "\nTotal TX bytes rate: %17"PRIu64
		   "\nTotal RX bytes rate: %17"PRIu64
		   "\nTotal rx H/w drops: %18"PRIu64
		   "\nTotal error pkt: %21"PRIu64
		   "\nTotal failed transmission: %11"PRIu64
		   "\nTotal rx mbuf failure: %15"PRIu64,
		   total_packets_tx,
		   total_packets_rx,
		   total_packets_dropped,
		    prev_total_packets_tx/timer_in_sec,
		    prev_total_packets_rx/timer_in_sec,
			eth_stats.obytes - old_eth_stats.obytes,
			eth_stats.ibytes - old_eth_stats.ibytes,
			eth_stats.imissed,
			eth_stats.ierrors,
			eth_stats.oerrors,
			eth_stats.rx_nombuf);
	printf("\n====================================================\n");
	rte_memcpy(&old_eth_stats, &eth_stats, sizeof(struct rte_eth_stats));
	fflush(stdout);
}

static void
write_stats(void)
{
	uint64_t total_packets_dropped, total_packets_tx, total_packets_rx, prev_total_packets_dropped, prev_total_packets_tx, prev_total_packets_rx, prev_dropped;
	uint64_t timer_in_sec = timer_period/rte_get_timer_hz();
	struct rte_eth_stats eth_stats;
	unsigned portid;
	int ret;


	total_packets_dropped = 0;
	total_packets_tx = 0;
	total_packets_rx = 0;
	prev_total_packets_rx = 0;
	prev_total_packets_tx = 0;
	prev_total_packets_dropped = 0;

	for (portid = 0; portid < RTE_MAX_ETHPORTS; portid++) {
		/* skip disabled ports */
		if ((l2fwd_enabled_port_mask & (1 << portid)) == 0)
			continue;
		unsigned tx = 0, rx = 0, dropped = 0, prev_tx = 0, prev_rx = 0;
		for(int i = 0; i < NUM_LCORES_FOR_RSS; i++){
			tx += port_statistics[i].tx;
			rx += port_statistics[i].rx;
			dropped += port_statistics[i].dropped;

			prev_tx = port_statistics[i].tx - port_statistics[i].prev_tx;
			port_statistics[i].prev_tx = port_statistics[i].tx;

			prev_rx = port_statistics[i].rx - port_statistics[i].prev_rx;
			port_statistics[i].prev_rx = port_statistics[i].rx;

			prev_dropped = port_statistics[i].dropped - port_statistics[i].prev_dropped;
			port_statistics[i].prev_dropped = port_statistics[i].dropped;

			prev_total_packets_rx += prev_rx;
			prev_total_packets_tx += prev_tx;
			prev_total_packets_dropped += prev_dropped;

			fprintf(log_file,"%"PRIu64",%"PRIu64",%"PRIu64",,",
			prev_tx/ timer_in_sec,
			prev_rx/ timer_in_sec,
			prev_dropped/timer_in_sec);
		} 
		total_packets_dropped += dropped;
		total_packets_tx += tx;
		total_packets_rx += rx;
	}
	// TODO: Update get port statistics to ensure that it
	// supports printing stats for multiple ports
	ret = rte_eth_stats_get(0, &eth_stats);
	fprintf(log_file, "%"PRIu64",%"PRIu64",%"PRIu64",%"PRIu64",%"PRIu64",%"PRIu64",%"PRIu64",%"PRIu64",%"PRIu64",\n",
		    prev_total_packets_tx/timer_in_sec,
		    prev_total_packets_rx/timer_in_sec,
			prev_total_packets_dropped/timer_in_sec,
			eth_stats.obytes - old_eth_stats.obytes,
			eth_stats.ibytes - old_eth_stats.ibytes,
			eth_stats.imissed - old_eth_stats.imissed,
			eth_stats.ierrors - old_eth_stats.ierrors,
			eth_stats.oerrors - old_eth_stats.oerrors,
			eth_stats.rx_nombuf - old_eth_stats.rx_nombuf);
	rte_memcpy(&old_eth_stats, &eth_stats, sizeof(struct rte_eth_stats));
	fflush(log_file);
}


static void
create_src_mac_flow(uint16_t portid)
{
	struct rte_flow_action action[2];
	struct rte_flow_item pattern[2];
	struct rte_flow_attr attr = {.ingress = 1, .egress = 0};
	struct rte_flow_error err;
	struct rte_flow_item_eth eth;
	struct rte_flow_action_queue queue;
	struct rte_flow *flow;
	void *tmp;
	int ret;
	static const struct rte_flow_item_eth eth_mask = {
        .hdr.dst_addr.addr_bytes = "\x00\x00\x00\x00\x00\x00",
        .hdr.src_addr.addr_bytes = "\xff\xff\xff\xff\xff\xff",
        .hdr.ether_type = RTE_BE16(0x0000),
    };
	attr.group = 0;
	uint16_t i;
	action[0].type = RTE_FLOW_ACTION_TYPE_QUEUE;
	action[0].conf = &queue;
	action[1].type = RTE_FLOW_ACTION_TYPE_END;

	pattern[0].type = RTE_FLOW_ITEM_TYPE_ETH;
	pattern[0].spec = &eth;
	pattern[0].mask = &eth_mask;
	pattern[0].last = NULL;
	pattern[1].type = RTE_FLOW_ITEM_TYPE_END;
	for(i = 0; i < NUM_LCORES_FOR_RSS; i++){
		tmp = &eth.hdr.src_addr;
		*((uint64_t *)tmp) = 0x001010101010 + ((uint64_t)i << 40);
		queue.index = i;
		printf("MAC address: " RTE_ETHER_ADDR_PRT_FMT "\n\n",
			RTE_ETHER_ADDR_BYTES(&eth.hdr.src_addr));

		ret = rte_flow_validate(portid, &attr, pattern, action, &err);
		if(ret){
			rte_exit(EXIT_FAILURE, "Invalid Flow %d %d\n", i, err.type);
		}
		flow = rte_flow_create(portid, &attr, pattern, action, &err);
		if(flow == NULL){
			rte_exit(EXIT_FAILURE, "Unable to create flow\n");
		}
	}
}

static void 
lookup_state(uint16_t dst_port, enum state *pkt_state)
{
	// struct in_addr ip_addr;
	// ip_addr.s_addr = src_ip;
	// RTE_LOG(INFO, L2FWD,"2LCOREID: %u, src_ip %s\n", lcore_id, inet_ntoa(ip_addr));
	// printf("LCORE %d\n", lcore_id);
	if(dst_port == PORT_0 && *pkt_state == CLOSED_0){
		// printf("CLOSED_1\n");
		*pkt_state = CLOSED_1;
	}
	else if(dst_port == PORT_1 && *pkt_state == CLOSED_1){
		// printf("CLOSED_2\n");
		*pkt_state = CLOSED_2;
	}
	else if(dst_port == PORT_2 && *pkt_state == CLOSED_2){
		// printf("OPEN\n");
		*pkt_state = OPEN;
	}
	else{
		// printf("CLOSED_0\n");
		*pkt_state = CLOSED_0;
	}
}

static void 
port_knocking_parse_ipv4(struct rte_mbuf *m, enum state *pkt_state, uint32_t *src_ip, bool *tcp_fin_flag)
{
	struct rte_ipv4_hdr *iphdr;
	// rte_be32_t src_ip; 
	uint16_t dst_port;
	struct rte_udp_hdr *udp;
	struct rte_tcp_hdr *tcp;

	/* Remove the Ethernet header from the input packet. 8< */
	// iphdr = (struct rte_ipv4_hdr *) rte_pktmbuf_adj(m, (uint16_t)sizeof(struct rte_ether_hdr));
	iphdr = (struct rte_ipv4_hdr *) (rte_pktmbuf_mtod(m, void *) + (uint16_t)sizeof(struct rte_ether_hdr));
	RTE_ASSERT(iphdr != NULL);

	*src_ip = iphdr->src_addr;

	switch (iphdr->next_proto_id) {
	case IPPROTO_TCP:
		tcp = (struct rte_tcp_hdr *)((unsigned char *)iphdr +
					sizeof(struct rte_ipv4_hdr));
		dst_port = rte_be_to_cpu_16(tcp->dst_port);
		*tcp_fin_flag = (tcp->tcp_flags & RTE_TCP_FIN_FLAG != 0);
		break;

	// case IPPROTO_UDP:
	// 	udp = (struct rte_udp_hdr *)((unsigned char *)iphdr +
	// 				sizeof(struct rte_ipv4_hdr));
	// 	dst_port = rte_be_to_cpu_16(udp->dst_port);
	// 	break;

	default:
		dst_port = 0;
		break;
	}

	lookup_state(dst_port, pkt_state);
}

static void
scr_state_update(struct rte_mbuf *m, unsigned portid, unsigned lcore_id, struct rte_hash *state_map)
{
	// Adjust offset by changing m->data_off
	uint32_t src_ip;
	uint16_t dst_port;
	bool tcp_fin_flag = false;
	// struct rte_ether_hdr *eth;
	// eth = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
	// printf("1 MAC address: " RTE_ETHER_ADDR_PRT_FMT "\n\n",
	// 		RTE_ETHER_ADDR_BYTES(&eth->src_addr));
	void *md_start = (void *) rte_pktmbuf_adj(m, (uint16_t)sizeof(struct rte_ether_hdr));
	uint16_t md_size = (NUM_PKTS_SCR - 1) * sizeof(struct metadata_elem);
	
	enum state pkt_state = CLOSED_0;
	int ret = rte_hash_lookup_data(state_map, &src_ip, (void**)&pkt_state);
	if(ret == -ENOENT){
		pkt_state = CLOSED_0;
		// rte_hash_add_key_data(state_map, &src_ip, (void *)pkt_state);
	}
	else if(ret < 0){
		rte_exit(EXIT_FAILURE, "State Table Invalid Parameters %d\n", ret);
	}
	if (md_start + md_size > md_start + m->data_len){
		// RTE_LOG(INFO, L2FWD,"1LCOREID: %u\n", lcore_id);
		port_knocking_parse_ipv4(m, &pkt_state, &src_ip, &tcp_fin_flag);
	}
	else{
		// TODO: Check if new session table is required
		enum state curr_state;
		struct metadata_elem *md_elem;
		md_elem = rte_pktmbuf_mtod_offset(m, void *, sizeof(struct metadata_elem)) ;

		for(int i = 0; i < NUM_PKTS_SCR - 1; i++){
			md_elem = rte_pktmbuf_mtod_offset(m, void *,i * sizeof(struct metadata_elem)) ;
			src_ip = md_elem->src_ip;
			dst_port = md_elem->dst_port;
			tcp_fin_flag = md_elem->tcp_fin_flag;
			// struct in_addr ip_addr;
			// ip_addr.s_addr = src_ip;
			// RTE_LOG(INFO, L2FWD,"2LCOREID: %u, src_ip %s\n", lcore_id, inet_ntoa(ip_addr));
			
			lookup_state(dst_port, &pkt_state);
			if(tcp_fin_flag){
				rte_hash_del_key(state_map, &src_ip);
			}
		}
		if(rte_pktmbuf_adj(m, md_size) == NULL)
			RTE_LOG(INFO, L2FWD, "Failed to fix mbuf\n");

		// eth = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
		// printf("2 MAC address: " RTE_ETHER_ADDR_PRT_FMT "\n\n",
		// 	RTE_ETHER_ADDR_BYTES(&eth->src_addr));
		port_knocking_parse_ipv4(m, &pkt_state, &src_ip, &tcp_fin_flag);
	}
	// Assume that for a given packet, irrespective of state update, the src ip will 
	// remain constant
	// printf("Lcores %d\n", lcore_id);
	if(tcp_fin_flag){
		rte_hash_del_key(state_map, &src_ip);
	}
	else{
		rte_hash_add_key_data(state_map, &src_ip, (void *)pkt_state);
	}
}

static void
l2fwd_mac_updating(struct rte_mbuf *m, unsigned dest_portid)
{
	struct rte_ether_hdr *eth;
	void *tmp;

	eth = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);

	/* 02:00:00:00:00:xx */
	// tmp = &eth->dst_addr.addr_bytes[0];
	// *((uint64_t *)tmp) = 0x000000000002 + ((uint64_t)dest_portid << 40);
	// Since there is just one port, swap src and dest mac
	// rte_ether_addr_copy(&eth->src_addr, &eth->dst_addr);
	if(USING_TRACE){
		*(uint64_t*) (&eth->dst_addr.addr_bytes[0]) = 0x9e0813d23fb8;
	}
	/* src addr */
	rte_ether_addr_copy(&l2fwd_ports_eth_addr[dest_portid], &eth->src_addr);
}

/* Simple forward. 8< */
static void
l2fwd_simple_forward(struct rte_mbuf *m, unsigned portid, unsigned lcore_id, struct rte_hash *state_map)
{
	scr_state_update(m, portid, lcore_id, state_map);
	unsigned dst_port;
	int sent;
	struct rte_eth_dev_tx_buffer *buffer;

	dst_port = l2fwd_dst_ports[portid];

	if (mac_updating)
		l2fwd_mac_updating(m, dst_port);

	// buffer = tx_buffer[dst_port];
	buffer = tx_buffer[lcore_id];
	sent = rte_eth_tx_buffer(dst_port, lcore_id, buffer, m);
	if (sent){
		port_statistics[lcore_id].tx += sent;
	}
}
/* >8 End of simple forward. */

/* main processing loop */
static void
l2fwd_main_loop(void)
{
	struct rte_mbuf *pkts_burst[MAX_PKT_BURST];
	struct rte_mbuf *m;
	int sent;
	unsigned lcore_id;
	uint64_t prev_tsc, diff_tsc, cur_tsc, timer_tsc, rx_burst_start_tsc, rx_burst_end_tsc;
	unsigned i, j, portid, nb_rx, tempi;
	struct lcore_queue_conf *qconf;
	const uint64_t drain_tsc = (rte_get_tsc_hz() + US_PER_S - 1) / US_PER_S *
			BURST_TX_DRAIN_US;
	struct rte_eth_dev_tx_buffer *buffer;

	
	prev_tsc = 0;
	timer_tsc = 0;

	rx_burst_start_tsc = 0;
	rx_burst_end_tsc = 0;
	tempi = 0;

	lcore_id = rte_lcore_id();
	qconf = &lcore_queue_conf[lcore_id];

	if (qconf->n_rx_port == 0) {
		RTE_LOG(INFO, L2FWD, "lcore %u has nothing to do\n", lcore_id);
		return;
	}

	// Hash table for state
	char name_buffer[20];
	snprintf(name_buffer, sizeof(name_buffer), "state_map%d", lcore_id);
	struct rte_hash_parameters params = { 
		.entries = MAX_IPV4_5TUPLES,
		.key_len = sizeof(rte_be32_t),
		.hash_func = rte_jhash,
		.socket_id = rte_socket_id(),
		.name = name_buffer,
	};
	
	state_map[lcore_id] = rte_hash_create(&params);

	RTE_LOG(INFO, L2FWD, "entering main loop on lcore %u\n", lcore_id);

	for (i = 0; i < qconf->n_rx_port; i++) {

		portid = qconf->rx_port_list[i];
		RTE_LOG(INFO, L2FWD, " -- lcoreid=%u portid=%u\n", lcore_id,
			portid);

	}

	while (!force_quit) {

		/* Drains TX queue in its main loop. 8< */
		cur_tsc = rte_rdtsc();

		/*
		 * TX burst queue drain
		 */
		diff_tsc = cur_tsc - prev_tsc;
		if (unlikely(diff_tsc > drain_tsc)) {

			for (i = 0; i < qconf->n_rx_port; i++) {

				portid = l2fwd_dst_ports[qconf->rx_port_list[i]];
				// buffer = tx_buffer[portid];

				// sent = rte_eth_tx_buffer_flush(portid, 0, buffer);
				// if (sent)
				// 	port_statistics[portid].tx += sent;
				
				buffer = tx_buffer[lcore_id];

				sent = rte_eth_tx_buffer_flush(portid, lcore_id, buffer);
				if (sent){
					port_statistics[lcore_id].tx += sent;
				}
				

			}

			/* if timer is enabled */
			if (timer_period > 0) {

				/* advance the timer */
				timer_tsc += diff_tsc;

				/* if timer has reached its timeout */
				if (unlikely(timer_tsc >= timer_period)) {

					/* do this only on main core */
					if (lcore_id == rte_get_main_lcore()) {
						if(WRITE_INTO_FILE)
							write_stats();
						else
							print_stats();
						/* reset the timer */
						timer_tsc = 0;
					}
				}
			}

			prev_tsc = cur_tsc;
		}
		/* >8 End of draining TX queue. */

		/* Read packet from RX queues. 8< */
		for (i = 0; i < qconf->n_rx_port; i++) {

			portid = qconf->rx_port_list[i];
			// TODO
			nb_rx = rte_eth_rx_burst(portid, lcore_id,
						 pkts_burst, MAX_PKT_BURST);
			// if(nb_rx > 0){
			// 	printf("\nCore %d, Num RX %d\n", lcore_id, nb_rx);
			// }
			

			if (unlikely(nb_rx == 0))
				continue;

			// temp_tsc = rte_rdtsc();
			burst_size[lcore_id][tempi] = nb_rx;
			rx_burst_start_tsc = rte_rdtsc();
			tsc_between_bursts_rx[lcore_id][tempi] = rx_burst_start_tsc - rx_burst_end_tsc;
			
			// port_statistics[portid].rx += nb_rx;
			port_statistics[lcore_id].rx += nb_rx;

			for (j = 0; j < nb_rx; j++) {
				m = pkts_burst[j];
				rte_prefetch0(rte_pktmbuf_mtod(m, void *));
				// l2fwd_simple_forward(m, portid, lcore_id);
				l2fwd_simple_forward(m, portid, lcore_id, state_map[lcore_id]);
			}
			rx_burst_end_tsc = rte_rdtsc();
			tsc_process_burst_rx[lcore_id][tempi] = rx_burst_end_tsc - rx_burst_start_tsc;
			tempi = (tempi+1) % LATENCY_SAMPLE_SIZE;
		}
		/* >8 End of read packet from RX queues. */
	}
}

static int
l2fwd_launch_one_lcore(__rte_unused void *dummy)
{
	l2fwd_main_loop();
	return 0;
}

/* display usage */
static void
l2fwd_usage(const char *prgname)
{
	printf("%s [EAL options] -- -p PORTMASK [-P] [-q NQ]\n"
	       "  -p PORTMASK: hexadecimal bitmask of ports to configure\n"
	       "  -P : Enable promiscuous mode\n"
	       "  -q NQ: number of queue (=ports) per lcore (default is 1)\n"
	       "  -T PERIOD: statistics will be refreshed each PERIOD seconds (0 to disable, 10 default, 86400 maximum)\n"
	       "  --no-mac-updating: Disable MAC addresses updating (enabled by default)\n"
	       "      When enabled:\n"
	       "       - The source MAC address is replaced by the TX port MAC address\n"
	       "       - The destination MAC address is replaced by 02:00:00:00:00:TX_PORT_ID\n"
	       "  --portmap: Configure forwarding port pair mapping\n"
	       "	      Default: alternate port pairs\n\n",
	       prgname);
}

static int
l2fwd_parse_portmask(const char *portmask)
{
	char *end = NULL;
	unsigned long pm;

	/* parse hexadecimal string */
	pm = strtoul(portmask, &end, 16);
	if ((portmask[0] == '\0') || (end == NULL) || (*end != '\0'))
		return 0;

	return pm;
}

static int
l2fwd_parse_port_pair_config(const char *q_arg)
{
	enum fieldnames {
		FLD_PORT1 = 0,
		FLD_PORT2,
		_NUM_FLD
	};
	unsigned long int_fld[_NUM_FLD];
	const char *p, *p0 = q_arg;
	char *str_fld[_NUM_FLD];
	unsigned int size;
	char s[256];
	char *end;
	int i;

	nb_port_pair_params = 0;

	while ((p = strchr(p0, '(')) != NULL) {
		++p;
		p0 = strchr(p, ')');
		if (p0 == NULL)
			return -1;

		size = p0 - p;
		if (size >= sizeof(s))
			return -1;

		memcpy(s, p, size);
		s[size] = '\0';
		if (rte_strsplit(s, sizeof(s), str_fld,
				 _NUM_FLD, ',') != _NUM_FLD)
			return -1;
		for (i = 0; i < _NUM_FLD; i++) {
			errno = 0;
			int_fld[i] = strtoul(str_fld[i], &end, 0);
			if (errno != 0 || end == str_fld[i] ||
			    int_fld[i] >= RTE_MAX_ETHPORTS)
				return -1;
		}
		if (nb_port_pair_params >= RTE_MAX_ETHPORTS/2) {
			printf("exceeded max number of port pair params: %hu\n",
				nb_port_pair_params);
			return -1;
		}
		port_pair_params_array[nb_port_pair_params].port[0] =
				(uint16_t)int_fld[FLD_PORT1];
		port_pair_params_array[nb_port_pair_params].port[1] =
				(uint16_t)int_fld[FLD_PORT2];
		++nb_port_pair_params;
	}
	port_pair_params = port_pair_params_array;
	return 0;
}

static unsigned int
l2fwd_parse_nqueue(const char *q_arg)
{
	char *end = NULL;
	unsigned long n;

	/* parse hexadecimal string */
	n = strtoul(q_arg, &end, 10);
	if ((q_arg[0] == '\0') || (end == NULL) || (*end != '\0'))
		return 0;
	if (n == 0)
		return 0;
	if (n >= MAX_RX_QUEUE_PER_LCORE)
		return 0;

	return n;
}

static int
l2fwd_parse_timer_period(const char *q_arg)
{
	char *end = NULL;
	int n;

	/* parse number string */
	n = strtol(q_arg, &end, 10);
	if ((q_arg[0] == '\0') || (end == NULL) || (*end != '\0'))
		return -1;
	if (n >= MAX_TIMER_PERIOD)
		return -1;

	return n;
}

static const char short_options[] =
	"p:"  /* portmask */
	"P"   /* promiscuous */
	"q:"  /* number of queues */
	"T:"  /* timer period */
	;

#define CMD_LINE_OPT_NO_MAC_UPDATING "no-mac-updating"
#define CMD_LINE_OPT_PORTMAP_CONFIG "portmap"

enum {
	/* long options mapped to a short option */

	/* first long only option value must be >= 256, so that we won't
	 * conflict with short options */
	CMD_LINE_OPT_NO_MAC_UPDATING_NUM = 256,
	CMD_LINE_OPT_PORTMAP_NUM,
};

static const struct option lgopts[] = {
	{ CMD_LINE_OPT_NO_MAC_UPDATING, no_argument, 0,
		CMD_LINE_OPT_NO_MAC_UPDATING_NUM},
	{ CMD_LINE_OPT_PORTMAP_CONFIG, 1, 0, CMD_LINE_OPT_PORTMAP_NUM},
	{NULL, 0, 0, 0}
};

/* Parse the argument given in the command line of the application */
static int
l2fwd_parse_args(int argc, char **argv)
{
	int opt, ret, timer_secs;
	char **argvopt;
	int option_index;
	char *prgname = argv[0];

	argvopt = argv;
	port_pair_params = NULL;

	while ((opt = getopt_long(argc, argvopt, short_options,
				  lgopts, &option_index)) != EOF) {

		switch (opt) {
		/* portmask */
		case 'p':
			l2fwd_enabled_port_mask = l2fwd_parse_portmask(optarg);
			if (l2fwd_enabled_port_mask == 0) {
				printf("invalid portmask\n");
				l2fwd_usage(prgname);
				return -1;
			}
			break;
		case 'P':
			promiscuous_on = 1;
			break;

		/* nqueue */
		case 'q':
			l2fwd_rx_queue_per_lcore = l2fwd_parse_nqueue(optarg);
			if (l2fwd_rx_queue_per_lcore == 0) {
				printf("invalid queue number\n");
				l2fwd_usage(prgname);
				return -1;
			}
			break;

		/* timer period */
		case 'T':
			timer_secs = l2fwd_parse_timer_period(optarg);
			if (timer_secs < 0) {
				printf("invalid timer period\n");
				l2fwd_usage(prgname);
				return -1;
			}
			timer_period = timer_secs;
			break;

		/* long options */
		case CMD_LINE_OPT_PORTMAP_NUM:
			ret = l2fwd_parse_port_pair_config(optarg);
			if (ret) {
				fprintf(stderr, "Invalid config\n");
				l2fwd_usage(prgname);
				return -1;
			}
			break;

		case CMD_LINE_OPT_NO_MAC_UPDATING_NUM:
			mac_updating = 0;
			break;

		default:
			l2fwd_usage(prgname);
			return -1;
		}
	}

	if (optind >= 0)
		argv[optind-1] = prgname;

	ret = optind-1;
	optind = 1; /* reset getopt lib */
	return ret;
}

/*
 * Check port pair config with enabled port mask,
 * and for valid port pair combinations.
 */
static int
check_port_pair_config(void)
{
	uint32_t port_pair_config_mask = 0;
	uint32_t port_pair_mask = 0;
	uint16_t index, i, portid;

	for (index = 0; index < nb_port_pair_params; index++) {
		port_pair_mask = 0;

		for (i = 0; i < NUM_PORTS; i++)  {
			portid = port_pair_params[index].port[i];
			if ((l2fwd_enabled_port_mask & (1 << portid)) == 0) {
				printf("port %u is not enabled in port mask\n",
				       portid);
				return -1;
			}
			if (!rte_eth_dev_is_valid_port(portid)) {
				printf("port %u is not present on the board\n",
				       portid);
				return -1;
			}

			port_pair_mask |= 1 << portid;
		}

		if (port_pair_config_mask & port_pair_mask) {
			printf("port %u is used in other port pairs\n", portid);
			return -1;
		}
		port_pair_config_mask |= port_pair_mask;
	}

	l2fwd_enabled_port_mask &= port_pair_config_mask;

	return 0;
}

/* Check the link status of all ports in up to 9s, and print them finally */
static void
check_all_ports_link_status(uint32_t port_mask)
{
#define CHECK_INTERVAL 100 /* 100ms */
#define MAX_CHECK_TIME 90 /* 9s (90 * 100ms) in total */
	uint16_t portid;
	uint8_t count, all_ports_up, print_flag = 0;
	struct rte_eth_link link;
	int ret;
	char link_status_text[RTE_ETH_LINK_MAX_STR_LEN];

	printf("\nChecking link status");
	fflush(stdout);
	for (count = 0; count <= MAX_CHECK_TIME; count++) {
		if (force_quit)
			return;
		all_ports_up = 1;
		RTE_ETH_FOREACH_DEV(portid) {
			if (force_quit)
				return;
			if ((port_mask & (1 << portid)) == 0)
				continue;
			memset(&link, 0, sizeof(link));
			ret = rte_eth_link_get_nowait(portid, &link);
			if (ret < 0) {
				all_ports_up = 0;
				if (print_flag == 1)
					printf("Port %u link get failed: %s\n",
						portid, rte_strerror(-ret));
				continue;
			}
			/* print link status if flag set */
			if (print_flag == 1) {
				rte_eth_link_to_str(link_status_text,
					sizeof(link_status_text), &link);
				printf("Port %d %s\n", portid,
				       link_status_text);
				continue;
			}
			/* clear all_ports_up flag if any link down */
			if (link.link_status == RTE_ETH_LINK_DOWN) {
				all_ports_up = 0;
				break;
			}
		}
		/* after finally printing all link status, get out */
		if (print_flag == 1)
			break;

		if (all_ports_up == 0) {
			printf(".");
			fflush(stdout);
			rte_delay_ms(CHECK_INTERVAL);
		}

		/* set the print_flag if all ports up or timeout */
		if (all_ports_up == 1 || count == (MAX_CHECK_TIME - 1)) {
			print_flag = 1;
			printf("done\n");
		}
	}
}

static void
signal_handler(int signum)
{
	if (signum == SIGINT || signum == SIGTERM) {
		printf("\n\nSignal %d received, preparing to exit...\n",
				signum);
		force_quit = true;
	}
}

int
main(int argc, char **argv)
{
	struct lcore_queue_conf *qconf;
	int ret;
	uint16_t nb_ports;
	uint16_t nb_ports_available = 0;
	uint16_t portid, last_port;
	uint64_t start_tsc_for_file;
	unsigned lcore_id, rx_lcore_id;
	unsigned nb_ports_in_mask = 0;
	unsigned int nb_lcores = 0;
	unsigned int nb_mbufs;

	start_tsc_for_file = rte_rdtsc();

	/* Init EAL. 8< */
	ret = rte_eal_init(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Invalid EAL arguments\n");
	argc -= ret;
	argv += ret;

	force_quit = false;
	signal(SIGINT, signal_handler);
	signal(SIGTERM, signal_handler);

	/* parse application arguments (after the EAL ones) */
	ret = l2fwd_parse_args(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Invalid L2FWD arguments\n");
	/* >8 End of init EAL. */

	printf("MAC updating %s\n", mac_updating ? "enabled" : "disabled");

	/* convert to number of cycles */
	timer_period *= rte_get_timer_hz();

	nb_ports = rte_eth_dev_count_avail();
	if (nb_ports == 0)
		rte_exit(EXIT_FAILURE, "No Ethernet ports - bye\n");

	if (port_pair_params != NULL) {
		if (check_port_pair_config() < 0)
			rte_exit(EXIT_FAILURE, "Invalid port pair config\n");
	}

	/* check port mask to possible port mask */
	if (l2fwd_enabled_port_mask & ~((1 << nb_ports) - 1))
		rte_exit(EXIT_FAILURE, "Invalid portmask; possible (0x%x)\n",
			(1 << nb_ports) - 1);

	/* Initialization of the driver. 8< */

	/* reset l2fwd_dst_ports */
	for (portid = 0; portid < RTE_MAX_ETHPORTS; portid++)
		l2fwd_dst_ports[portid] = 0;
	last_port = 0;

	/* populate destination port details */
	if (port_pair_params != NULL) {
		uint16_t idx, p;

		for (idx = 0; idx < (nb_port_pair_params << 1); idx++) {
			p = idx & 1;
			portid = port_pair_params[idx >> 1].port[p];
			l2fwd_dst_ports[portid] =
				port_pair_params[idx >> 1].port[p ^ 1];
		}
	} else {
		RTE_ETH_FOREACH_DEV(portid) {
			/* skip ports that are not enabled */
			if ((l2fwd_enabled_port_mask & (1 << portid)) == 0)
				continue;

			if (nb_ports_in_mask % 2) {
				l2fwd_dst_ports[portid] = last_port;
				l2fwd_dst_ports[last_port] = portid;
			} else {
				last_port = portid;
			}

			nb_ports_in_mask++;
		}
		if (nb_ports_in_mask % 2) {
			printf("Notice: odd number of ports in portmask.\n");
			l2fwd_dst_ports[last_port] = last_port;
		}
	}

		/* >8 End of initialization of the driver. */

	rx_lcore_id = 0;
	qconf = NULL;

	/* Initialize the port/queue configuration of each logical core */
	RTE_ETH_FOREACH_DEV(portid) {
		/* skip ports that are not enabled */
		// RSS
		for(int i = 0; i < NUM_LCORES_FOR_RSS; i++){
			if ((l2fwd_enabled_port_mask & (1 << portid)) == 0)
			continue;

			/* get the lcore_id for this port */
			while (rte_lcore_is_enabled(rx_lcore_id) == 0 ||
				lcore_queue_conf[rx_lcore_id].n_rx_port ==
				l2fwd_rx_queue_per_lcore) {
				rx_lcore_id++;
				if (rx_lcore_id >= RTE_MAX_LCORE)
					rte_exit(EXIT_FAILURE, "Not enough cores\n");
			}

			if (qconf != &lcore_queue_conf[rx_lcore_id]) {
				/* Assigned a new logical core in the loop above. */
				qconf = &lcore_queue_conf[rx_lcore_id];
				nb_lcores++;
			}

			qconf->rx_port_list[qconf->n_rx_port] = portid;
			qconf->n_rx_port++;
			printf("Lcore %u: RX port %u TX port %u\n", rx_lcore_id++,
				portid, l2fwd_dst_ports[portid]);
		}
		
	}

	


	nb_mbufs = RTE_MAX(nb_ports * nb_lcores *( nb_rxd + nb_txd + MAX_PKT_BURST +
		 MEMPOOL_CACHE_SIZE), 8192U);

	/* Create the mbuf pool. 8< */
	l2fwd_pktmbuf_pool = rte_pktmbuf_pool_create("mbuf_pool", nb_mbufs,
		MEMPOOL_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE,
		rte_socket_id());
	if (l2fwd_pktmbuf_pool == NULL)
		rte_exit(EXIT_FAILURE, "Cannot init mbuf pool\n");
	/* >8 End of create the mbuf pool. */

	/* Initialise each port */
	RTE_ETH_FOREACH_DEV(portid) {
		struct rte_eth_rxconf rxq_conf;
		struct rte_eth_txconf txq_conf;
		struct rte_eth_conf local_port_conf = port_conf;
		struct rte_eth_dev_info dev_info;

		/* skip ports that are not enabled */
		if ((l2fwd_enabled_port_mask & (1 << portid)) == 0) {
			printf("Skipping disabled port %u\n", portid);
			continue;
		}
		nb_ports_available++;

		/* init port */
		printf("Initializing port %u... ", portid);
		fflush(stdout);

		ret = rte_eth_dev_info_get(portid, &dev_info);
		if (ret != 0)
			rte_exit(EXIT_FAILURE,
				"Error during getting device (port %u) info: %s\n",
				portid, strerror(-ret));

		if (dev_info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE)
			local_port_conf.txmode.offloads |=
				RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE;




		// Setting up RSS
		// printf("\nPort Info, reta %d, max_rx %d, rss_offload %lx\n", dev_info.reta_size, dev_info.max_rx_queues, dev_info.flow_type_rss_offloads);
		// uint64_t rss_hf = RTE_ETH_RSS_IP;
		// local_port_conf.rx_adv_conf.rss_conf.rss_hf = rss_hf & dev_info.flow_type_rss_offloads;
		// if(local_port_conf.rx_adv_conf.rss_conf.rss_hf == 0){
		// 	printf("\nIncompatible Hash Function\n");
		// }

		/* Configure the number of queues for a port. */
		// RSS
		ret = rte_eth_dev_configure(portid, NUM_LCORES_FOR_RSS, NUM_LCORES_FOR_RSS, &local_port_conf);
		if (ret < 0)
			rte_exit(EXIT_FAILURE, "Cannot configure device: err=%d, port=%u\n",
				  ret, portid);
		/* >8 End of configuration of the number of queues for a port. */

		ret = rte_eth_dev_adjust_nb_rx_tx_desc(portid, &nb_rxd,
						       &nb_txd);
		if (ret < 0)
			rte_exit(EXIT_FAILURE,
				 "Cannot adjust number of descriptors: err=%d, port=%u\n",
				 ret, portid);

		ret = rte_eth_macaddr_get(portid,
					  &l2fwd_ports_eth_addr[portid]);
		if (ret < 0)
			rte_exit(EXIT_FAILURE,
				 "Cannot get MAC address: err=%d, port=%u\n",
				 ret, portid);

		// RSS
		/* init 4 RX queue */
		fflush(stdout);
		rxq_conf = dev_info.default_rxconf;
		rxq_conf.offloads = local_port_conf.rxmode.offloads;
		/* RX queue setup. 8< */
		for(int i = 0; i < NUM_LCORES_FOR_RSS; i++){
			ret = rte_eth_rx_queue_setup(portid, i, nb_rxd,
					     rte_eth_dev_socket_id(portid),
					     NULL,
					     l2fwd_pktmbuf_pool);
			if (ret < 0)
				rte_exit(EXIT_FAILURE, "rte_eth_rx_queue_setup:err=%d, port=%u\n",
					ret, portid);
			/* >8 End of RX queue setup. */
		}
		

		/* Init 4 TX queue on each port. 8< */
		fflush(stdout);
		txq_conf = dev_info.default_txconf;
		txq_conf.offloads = local_port_conf.txmode.offloads;
		for(int i = 0; i < NUM_LCORES_FOR_RSS; i++){
			ret = rte_eth_tx_queue_setup(portid, i, nb_txd,
					rte_eth_dev_socket_id(portid),
					&txq_conf);
			if (ret < 0)
				rte_exit(EXIT_FAILURE, "rte_eth_tx_queue_setup:err=%d, port=%u\n",
					ret, portid);
			/* >8 End of init one TX queue on each port. */
		}

		/* Initialize TX buffers */
		for(int i = 0; i < NUM_LCORES_FOR_RSS; i++){
			// tx_buffer[portid] = rte_zmalloc_socket("tx_buffer",
			// 		RTE_ETH_TX_BUFFER_SIZE(MAX_PKT_BURST), 0,
			// 		rte_eth_dev_socket_id(portid));
			// if (tx_buffer[portid] == NULL)
			// 	rte_exit(EXIT_FAILURE, "Cannot allocate buffer for tx on port %u\n",
			// 			portid);

			// rte_eth_tx_buffer_init(tx_buffer[portid], MAX_PKT_BURST);

			// ret = rte_eth_tx_buffer_set_err_callback(tx_buffer[portid],
			// 		rte_eth_tx_buffer_count_callback,
			// 		&port_statistics[portid].dropped);
			// if (ret < 0)
			// 	rte_exit(EXIT_FAILURE,
			// 	"Cannot set error callback for tx buffer on port %u\n",
			// 		portid);
			char temp[12];
			snprintf(temp,12,"tx_buffer%d", i);
			tx_buffer[i] = rte_zmalloc_socket(temp,
					RTE_ETH_TX_BUFFER_SIZE(MAX_PKT_BURST), 0,
					rte_eth_dev_socket_id(portid));

			if (tx_buffer[i] == NULL)
				rte_exit(EXIT_FAILURE, "Cannot allocate buffer for tx on port %u\n",
						portid);

			rte_eth_tx_buffer_init(tx_buffer[i], MAX_PKT_BURST);

			ret = rte_eth_tx_buffer_set_err_callback(tx_buffer[i],
					rte_eth_tx_buffer_count_callback,
					&port_statistics[i].dropped);
			if (ret < 0)
				rte_exit(EXIT_FAILURE,
				"Cannot set error callback for tx buffer on port %u\n",
					portid);
		}

		ret = rte_eth_dev_set_ptypes(portid, RTE_PTYPE_UNKNOWN, NULL,
					     0);
		if (ret < 0)
			printf("Port %u, Failed to disable Ptype parsing\n",
					portid);


		/* Start device */
		ret = rte_eth_dev_start(portid);
		if (ret < 0)
			rte_exit(EXIT_FAILURE, "rte_eth_dev_start:err=%d, port=%u\n",
				  ret, portid);

		printf("done: \n");
		if (promiscuous_on) {
			ret = rte_eth_promiscuous_enable(portid);
			if (ret != 0)
				rte_exit(EXIT_FAILURE,
					"rte_eth_promiscuous_enable:err=%s, port=%u\n",
					rte_strerror(-ret), portid);
		}

		printf("Port %u, MAC address: " RTE_ETHER_ADDR_PRT_FMT "\n\n",
			portid,
			RTE_ETHER_ADDR_BYTES(&l2fwd_ports_eth_addr[portid]));

		/* initialize port stats */
		memset(&port_statistics, 0, sizeof(port_statistics));

		// Reset Port statistics
		ret = rte_eth_stats_reset(portid);
		if(ret < 0)
			rte_exit(EXIT_FAILURE, "rte_eth_stats_reset: err=%s, port=%u\n", 
			rte_strerror(-ret), portid);

		// Create flow
		create_src_mac_flow(portid);

		// Create a file to write stats into
		if(WRITE_INTO_FILE){
			char name_buffer[100];
			snprintf(name_buffer, sizeof(name_buffer), "../stats/%"PRIu8"core_portknock_scr_%"PRIu32".csv", NUM_LCORES_FOR_RSS, (uint32_t) ((start_tsc_for_file & (uint64_t) 0xFFFFFFFF00000000) >> 32));
			log_file = fopen(name_buffer, "w");
			uint8_t i;
			for(i = 0; i < NUM_LCORES_FOR_RSS; i++){
				fprintf(log_file, "Lcore %u,,,,",i);
			}
			fprintf(log_file, "Aggregate statistics,,,,,,,,,,\n");
			for(i = 0; i < NUM_LCORES_FOR_RSS; i++){
				fprintf(log_file, "Current TX rate (PPS),Current RX rate (PPS),Current Drop rate (PPS),,");
			}
			fprintf(log_file, "Total TX rate (PPS),Total RX rate (PPS),Total Drop rate (PPS),"
				"Total TX bytes rate,Total RX bytes rate,Total rx H/w drops rate,Total error pkt rate,"
				"Total failed transmission rate,Total rx mbuf failure rate\n");
			fflush(log_file);
		}
	}

	if (!nb_ports_available) {
		rte_exit(EXIT_FAILURE,
			"All available ports are disabled. Please set portmask.\n");
	}

	check_all_ports_link_status(l2fwd_enabled_port_mask);

	ret = 0;
	/* launch per-lcore init on every lcore */
	rte_eal_mp_remote_launch(l2fwd_launch_one_lcore, NULL, CALL_MAIN);
	RTE_LCORE_FOREACH_WORKER(lcore_id) {
		if (rte_eal_wait_lcore(lcore_id) < 0) {
			ret = -1;
			break;
		}
	}

	RTE_ETH_FOREACH_DEV(portid) {
		// Close filepointer
		if(WRITE_INTO_FILE)
			fclose(log_file);
		if ((l2fwd_enabled_port_mask & (1 << portid)) == 0)
			continue;
		printf("Closing port %d...", portid);
		ret = rte_eth_dev_stop(portid);
		if (ret != 0)
			printf("rte_eth_dev_stop: err=%d, port=%d\n",
			       ret, portid);
		rte_eth_dev_close(portid);
		printf(" Done\n");
	}

	char name_buffer[100];
	snprintf(name_buffer, sizeof(name_buffer), "../stats/%"PRIu8"core_portknock_scr_latency_%"PRIu32".csv", NUM_LCORES_FOR_RSS, (uint32_t) ((start_tsc_for_file & (uint64_t) 0xFFFFFFFF00000000) >> 32));
	log_file = fopen(name_buffer, "w");
	uint8_t i;
	for(i = 0; i < NUM_LCORES_FOR_RSS; i++){
		fprintf(log_file, "core %u,core %u,core %u,",i,i,i);
	}
	fprintf(log_file, "\n");
	for(i = 0; i < NUM_LCORES_FOR_RSS; i++){
		fprintf(log_file, "Time Between Bursts, Time to Process Burst, Burst Size,");
	}
	fprintf(log_file, "\n");
	for(i = 0; i < LATENCY_SAMPLE_SIZE; i++){
		for(int j = 0; j < NUM_LCORES_FOR_RSS; j++){
			fprintf(log_file, "%"PRIu64",%"PRIu64",%"PRIu64",",
			tsc_between_bursts_rx[j][i]/(rte_get_tsc_hz()/NS_PER_S),
			tsc_process_burst_rx[j][i]/(rte_get_tsc_hz()/NS_PER_S),
			burst_size[j][i]);
		}
		fprintf(log_file, "\n");
	}
	fflush(log_file);
	fclose(log_file);
	// printf("Latency Stats");
	// for(int i = 0; i < NUM_LCORES_FOR_RSS; i++){
	// 	uint64_t min_btw=-1, max_btw=0, avg_btw=0, curr_btw=0, min_proc=-1, max_proc=0, avg_proc=0, curr_proc=0;
	// 	printf("\n\nCore %d\n", i);
	// 	for(int j = 0; j < 64; j++){
	// 		curr_btw = tsc_between_bursts_rx[i][j]/(rte_get_tsc_hz()/NS_PER_S);
	// 		min_btw = RTE_MIN(min_btw, curr_btw);
	// 		max_btw = RTE_MAX(max_btw, curr_btw);
	// 		avg_btw += curr_btw;
			
	// 		curr_proc = tsc_process_burst_rx[i][j]/(rte_get_tsc_hz()/NS_PER_S);
	// 		min_proc = RTE_MIN(curr_proc, min_proc);
	// 		max_proc = RTE_MAX(curr_proc, max_proc);
	// 		avg_proc += curr_proc;
	// 	}
	// 	printf("Time Between Bursts: Min: %"PRIu64" Max: %"PRIu64" Avg: %"PRIu64"\n", min_btw, max_btw, avg_btw/64);
	// 	printf("Time to Process Bursts: Min: %"PRIu64" Max: %"PRIu64" Avg: %"PRIu64"\n", min_proc, max_proc, avg_proc/64);
	// }

	/* clean up the EAL */
	rte_eal_cleanup();
	printf("Bye...\n");

	return ret;
}
