#ifndef _STATE_H_
#define _STATE_H_

#include "lib.h"
#include "trie.h"
#include "mylist.h"
#include "protocols.h"
#include <arpa/inet.h>
#include <string.h>

typedef enum {
	STATE_INITIAL,
	STATE_RECVEIVE,
	STATE_CHECK_MAC,
	STATE_CHECK_SUM,
	STATE_CHECK_TTL,
	STATE_RESPOND_TO_ARP_REQUEST,
	STATE_ARP_REPLY_RECV,
	STATE_LPM,
	STATE_CHECK_ARP_TABLE,
	STATE_DECREASE_TTL,
	STATE_SEND_IP_PACKET,
	STATE_SEND_ARP_REQUEST,
	STATE_ROUTER_ICMP,
	STATE_HOST_UNREACHABLE,
	STATE_TIME_EXCEEDED,
	STATE_ICMP_ERROR,
	NUM_STATES
} state_t;

typedef struct {
	struct route_table_entry *route_table;
	uint32_t route_table_size;
	char *rtable_path;
	char *buf;
	int len;
	int recv_interface;
	TrieP trie;
	struct arp_entry *arp_table;
	uint32_t arp_table_size;
	struct route_table_entry *lpm_entry;
	ListP list;
	uint8_t icmp_errortype;
} instance_data, *instance_data_t;

typedef state_t state_func_t(instance_data_t data);

state_t do_state_initial(instance_data_t data);
state_t do_state_recv(instance_data_t data);
state_t do_check_mac(instance_data_t data);
state_t do_check_sum(instance_data_t data);
state_t do_check_ttl(instance_data_t data);
state_t do_respond_to_arp(instance_data_t data);
state_t do_compute_arp_reply(instance_data_t data);
state_t do_lpm(instance_data_t data);
state_t do_check_arp_table(instance_data_t data);
state_t do_decrease_ttl(instance_data_t data);
state_t do_send_ip_packet(instance_data_t data);
state_t do_send_arp_request(instance_data_t data);
state_t do_router_icmp(instance_data_t data);
state_t do_host_unreachable(instance_data_t data);
state_t do_time_exceeded(instance_data_t data);
state_t do_icmp_error(instance_data_t data);

state_t run_state(state_t cur_state, instance_data_t data);

#endif /* _STATE_H_ */
