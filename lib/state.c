
#include "state.h"

state_func_t* const state_table[NUM_STATES] = {
	do_state_initial,
	do_state_recv,
	do_check_mac,
	do_check_sum,
	do_check_ttl,
	do_respond_to_arp,
	do_compute_arp_reply,
	do_lpm,
	do_check_arp_table,
	do_decrease_ttl,
	do_send_ip_packet,
	do_send_arp_request,
	do_router_icmp,
	do_host_unreachable,
	do_time_exceeded,
	do_icmp_error
};

state_t run_state(state_t cur_state, instance_data_t data) {
    return state_table[cur_state](data);
};

state_t do_state_initial(instance_data_t data) {
	data->route_table_size = read_rtable(data->rtable_path, data->route_table);
	data->trie = newTrie();
	completeTrie(data->trie, data->route_table, data->route_table_size);
	data->arp_table_size = 0;
	return STATE_RECVEIVE;
}

state_t do_state_recv(instance_data_t data) {
	int interface;
	size_t len;

	interface = recv_from_any_link(data->buf, &len);
	DIE(interface < 0, "recv_from_any_links");

	data->recv_interface = interface;
	data->len = len;

	return STATE_CHECK_MAC;
}

state_t do_check_mac(instance_data_t data) {
	struct ether_header *eth_hdr = (struct ether_header *) data->buf;

	uint8_t broadcast_mac[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
	uint8_t interface_mac[6];
	get_interface_mac(data->recv_interface, interface_mac);

	int broadcast = 1;

	for (int i = 0; i < 6; i++) {
		if (broadcast_mac[i] != eth_hdr->ether_dhost[i]) {
			broadcast = 0;
		}
	}

	if (broadcast == 1) {
		if (ntohs(eth_hdr->ether_type) == 0x806) {
			return STATE_RESPOND_TO_ARP_REQUEST;
		} else {
			memset(data->buf, 0, MAX_PACKET_LEN);
			return STATE_RECVEIVE;
		}
	}

	int my_mac = 1;
	for (int i = 0; i < 6; i++) {
		if (interface_mac[i] != eth_hdr->ether_dhost[i]) {
			my_mac = 0;
		}
	}

	if (my_mac == 1) {
		if (ntohs(eth_hdr->ether_type) == 0x806) {
			struct arp_header *arp_hdr = (struct arp_header *) (data->buf + sizeof(struct ether_header));

			if (ntohs(arp_hdr->op) == 1)
				return STATE_RESPOND_TO_ARP_REQUEST;

			return STATE_ARP_REPLY_RECV;
		}
		else if (ntohs(eth_hdr->ether_type) == 0x800)
			return STATE_CHECK_SUM;
	}

	memset(data->buf, 0, MAX_PACKET_LEN);
	return STATE_RECVEIVE;
}

state_t do_check_sum(instance_data_t data) {
	struct iphdr *ip_hdr = (struct iphdr *) (data->buf + sizeof(struct ether_header));

	uint16_t old_checksum = ntohs(ip_hdr->check);

	ip_hdr->check = 0;
	uint16_t new_checksum = checksum((uint16_t *) ip_hdr, sizeof(struct iphdr));

	if (old_checksum != new_checksum) {
		memset(data->buf, 0, MAX_PACKET_LEN);
		return STATE_RECVEIVE;
	}

	ip_hdr->check = htons(new_checksum);

	return STATE_CHECK_TTL;
}

state_t do_check_ttl(instance_data_t data) {
	struct iphdr *ip_hdr = (struct iphdr *) (data->buf + sizeof(struct ether_header));

	if (ip_hdr->ttl <= 1)
		return STATE_TIME_EXCEEDED;

	return STATE_LPM;
}

state_t do_respond_to_arp(instance_data_t data) {
	uint8_t interface_mac[6];
	get_interface_mac(data->recv_interface, interface_mac);

	char *my_ip_str = get_interface_ip(data->recv_interface);

	uint32_t my_ip = 0;  // BIG ENDIAN
	int i = 0;
	char *p = strtok(my_ip_str, ".");
	while (p != NULL) {
		*(((unsigned char *)&my_ip) + i) = (unsigned char) atoi(p);
		p = strtok(NULL, ".");
		i++;
	}

	struct arp_header *arp_hdr = (struct arp_header *) (data->buf + sizeof(struct ether_header));

	if (my_ip != arp_hdr->tpa) {
		memset(data->buf, 0, MAX_PACKET_LEN);
		return STATE_RECVEIVE;
	}

	uint16_t old_op = ntohs(arp_hdr->op);
	if (old_op != 1) {
		memset(data->buf, 0, MAX_PACKET_LEN);
		return STATE_RECVEIVE;
	}

	uint16_t new_op = htons(2);
	arp_hdr->op = new_op;

	uint32_t target_ip = arp_hdr->tpa;
	arp_hdr->tpa = arp_hdr->spa;
	arp_hdr->spa = target_ip;

	struct ether_header *eth_hdr = (struct ether_header *) data->buf;

	for (i = 0; i < 6; i++) {
		eth_hdr->ether_shost[i] = interface_mac[i];
		eth_hdr->ether_dhost[i] = arp_hdr->sha[i];
		arp_hdr->tha[i] = arp_hdr->sha[i];
		arp_hdr->sha[i] = interface_mac[i];
	}

	send_to_link(data->recv_interface, data->buf, sizeof(struct ether_header) + sizeof(struct arp_header));

	memset(data->buf, 0, MAX_PACKET_LEN);
	return STATE_RECVEIVE;
}

state_t do_compute_arp_reply(instance_data_t data) {
	struct arp_header *arp_hdr = (struct arp_header *) (data->buf + sizeof(struct ether_header));

	ListP foundIP = searchNode(arp_hdr->spa, &(data->list));

	if (foundIP == NULL) {
		memset(data->buf, 0, MAX_PACKET_LEN);
		return STATE_RECVEIVE;
	}

	for (int i = 0; i < 6; i++) {
		data->arp_table[data->arp_table_size].mac[i] = arp_hdr->sha[i];
		data->arp_table[data->arp_table_size].ip = arp_hdr->spa;
	}

	data->arp_table_size++;

	struct ether_header *eth_hdr = (struct ether_header *) foundIP->buf;

	for (int i = 0; i < 6; i++) {
		eth_hdr->ether_dhost[i] = arp_hdr->sha[i];
		eth_hdr->ether_shost[i] = arp_hdr->tha[i];
	}

	memset(data->buf, 0, MAX_PACKET_LEN);

	memcpy(data->buf, foundIP->buf, foundIP->len);
	data->len = foundIP->len;
	data->lpm_entry = foundIP->lpm_entry;

	free(foundIP->buf);
	free(foundIP);

	return STATE_DECREASE_TTL;
}

state_t do_lpm(instance_data_t data) {
	struct iphdr *ip_hdr = (struct iphdr *) (data->buf + sizeof(struct ether_header));

	uint32_t dest_ip = ntohl(ip_hdr->daddr);

	char *my_ip_str = get_interface_ip(data->recv_interface);

	uint32_t my_ip = 0;
	int i = 0;
	char *p = strtok(my_ip_str, ".");
	while (p != NULL) {
		*(((unsigned char *)&my_ip) + 3 - i) = (unsigned char) atoi(p);
		p = strtok(NULL, ".");
		i++;
	}

	if (dest_ip == my_ip)
		return STATE_ROUTER_ICMP;

	uint32_t first_bit_mask = 1 << 31;

	TrieNodeP current_node = NULL, lastFound = NULL;

	if ((dest_ip & first_bit_mask) == first_bit_mask)
		current_node = data->trie->oneRoot;
	else
		current_node = data->trie->zeroRoot;

	while (current_node != NULL) {
		if (current_node->ipEntry != NULL)
			lastFound = current_node;

		dest_ip = dest_ip << 1;

		if ((dest_ip & first_bit_mask) == first_bit_mask)
			current_node = current_node->oneChild;
		else
			current_node = current_node->zeroChild;
	}

	if (lastFound == NULL)
		return STATE_HOST_UNREACHABLE;

	data->lpm_entry = lastFound->ipEntry;

	return STATE_CHECK_ARP_TABLE;
}

state_t do_check_arp_table(instance_data_t data) {
	struct ether_header *eth_hdr = (struct ether_header *) data->buf;

	int g = 0;
	uint8_t interface_mac[6];
	get_interface_mac(data->lpm_entry->interface, interface_mac);

	for (int i = 0; i < data->arp_table_size && g == 0; i++) {
		if (data->arp_table[i].ip == data->lpm_entry->next_hop) {
			for (int j = 0; j < 6; j++) {
				eth_hdr->ether_dhost[j] = data->arp_table[i].mac[j];
				eth_hdr->ether_shost[j] = interface_mac[j];
			}
			g = 1;
		}
	}

	if (g == 0)
		return STATE_SEND_ARP_REQUEST;

	return STATE_DECREASE_TTL;
}

state_t do_decrease_ttl(instance_data_t data) {
	struct iphdr *ip_hdr = (struct iphdr *) (data->buf + sizeof(struct ether_header));

	uint8_t new_ttl = ip_hdr->ttl - 1;
	ip_hdr->ttl = new_ttl;

	ip_hdr->check = 0;
	uint16_t new_checksum = checksum((uint16_t *) ip_hdr, sizeof(struct iphdr));

	ip_hdr->check = htons(new_checksum);

	return STATE_SEND_IP_PACKET;
}

state_t do_send_ip_packet(instance_data_t data) {
	send_to_link(data->lpm_entry->interface, data->buf, data->len);

	memset(data->buf, 0, MAX_PACKET_LEN);
	return STATE_RECVEIVE;
}

state_t do_send_arp_request(instance_data_t data) {
	data->list = addNode(data->lpm_entry, data->buf, data->list, data->len);

	char new_packet[MAX_PACKET_LEN];
	memset(new_packet, 0, MAX_PACKET_LEN);

	struct ether_header *eth_hdr = (struct ether_header *) new_packet;
	struct arp_header *arp_hdr = (struct arp_header *) (new_packet + sizeof(struct ether_header));

	uint8_t interface_mac[6];
	get_interface_mac(data->lpm_entry->interface, interface_mac);

	for (int i = 0; i < 6; i++) {
		eth_hdr->ether_shost[i] = interface_mac[i];
		eth_hdr->ether_dhost[i] = 0xFF;
	}
	eth_hdr->ether_type = htons(0x806);

	arp_hdr->htype = htons(1);
	arp_hdr->hlen = 6;
	arp_hdr->ptype = htons(0x0800);
	arp_hdr->plen = 4;
	arp_hdr->op = htons(1);

	for (int i = 0; i < 6; i++) {
		arp_hdr->sha[i] = interface_mac[i];
		arp_hdr->tha[i] = 0;
	}

	char *my_ip_str = get_interface_ip(data->lpm_entry->interface);

	uint32_t my_ip = 0;  // BIG ENDIAN
	int i = 0;
	char *p = strtok(my_ip_str, ".");
	while (p != NULL) {
		*(((unsigned char *)&my_ip) + i) = (unsigned char) atoi(p);
		p = strtok(NULL, ".");
		i++;
	}

	arp_hdr->spa = my_ip;
	arp_hdr->tpa = data->lpm_entry->next_hop;

	send_to_link(data->lpm_entry->interface, new_packet, sizeof(struct ether_header) + sizeof(struct arp_header));

	memset(data->buf, 0, MAX_PACKET_LEN);
	return STATE_RECVEIVE;
}

state_t do_router_icmp(instance_data_t data) {
	struct ether_header *eth_hdr = (struct ether_header *) data->buf;
	struct iphdr *ip_hdr = (struct iphdr *) (data->buf + sizeof(struct ether_header));

	if (ip_hdr->protocol != 1) {
		memset(data->buf, 0, MAX_PACKET_LEN);
		return STATE_RECVEIVE;
	}

	struct icmphdr *icmp_hdr = (struct icmphdr *) (data->buf + sizeof(struct ether_header) + sizeof(struct iphdr));

	for (int i = 0; i < 6; i++) {
		unsigned char aux = eth_hdr->ether_dhost[i];
		eth_hdr->ether_dhost[i] = eth_hdr->ether_shost[i];
		eth_hdr->ether_shost[i] = aux;
	}

	uint32_t aux = ip_hdr->saddr;
	ip_hdr->saddr = ip_hdr->daddr;
	ip_hdr->daddr = aux;

	icmp_hdr->type = 0;
	icmp_hdr->code = 0;

	ip_hdr->check = 0;
	uint16_t new_ipv4_checksum = checksum((uint16_t *) ip_hdr, sizeof(struct iphdr));
	ip_hdr->check = htons(new_ipv4_checksum);

	icmp_hdr->checksum = 0;
	uint16_t new_icmp_checksum = checksum((uint16_t *) icmp_hdr, ntohs(ip_hdr->tot_len) - sizeof(struct iphdr));
	icmp_hdr->checksum = htons(new_icmp_checksum);

	send_to_link(data->recv_interface, data->buf, data->len);

	memset(data->buf, 0, MAX_PACKET_LEN);
	return STATE_RECVEIVE;
}

state_t do_host_unreachable(instance_data_t data) {
	data->icmp_errortype = 3;
	return STATE_ICMP_ERROR;
}

state_t do_time_exceeded(instance_data_t data) {
	data->icmp_errortype = 11;
	return STATE_ICMP_ERROR;
}

state_t do_icmp_error(instance_data_t data) {
	char new_packet[MAX_PACKET_LEN];
	memset(new_packet, 0, MAX_PACKET_LEN);

	struct ether_header *eth_hdr = (struct ether_header *) data->buf;
	struct iphdr *ip_hdr = (struct iphdr *) (data->buf + sizeof(struct ether_header));

	struct ether_header *new_eth_hdr = (struct ether_header *) new_packet;
	struct iphdr *new_ip_hdr = (struct iphdr *) (new_packet + sizeof(struct ether_header));

	for (int i = 0; i < 6; i++) {
		new_eth_hdr->ether_shost[i] = eth_hdr->ether_dhost[i];
		new_eth_hdr->ether_dhost[i] = eth_hdr->ether_shost[i];
	}

	new_eth_hdr->ether_type = htons(0x800);

	char *my_ip_str = get_interface_ip(data->recv_interface);

	uint32_t my_ip = 0;  // BIG ENDIAN
	int i = 0;
	char *p = strtok(my_ip_str, ".");
	while (p != NULL) {
		*(((unsigned char *)&my_ip) + i) = (unsigned char) atoi(p);
		p = strtok(NULL, ".");
		i++;
	}

	new_ip_hdr->daddr = ip_hdr->saddr;
	new_ip_hdr->saddr = my_ip;
	new_ip_hdr->tot_len = htons(56);
	new_ip_hdr->ttl = 64;
	new_ip_hdr->protocol = 1;
	new_ip_hdr->frag_off = 0;
	new_ip_hdr->version = 4;
	new_ip_hdr->ihl = 5;
	new_ip_hdr->tos = 0;
	new_ip_hdr->id = htons(1);
	new_ip_hdr->check = 0;

	uint16_t new_ipv4_checksum = checksum((uint16_t *) new_ip_hdr, sizeof(struct iphdr));
	new_ip_hdr->check = htons(new_ipv4_checksum);

	struct icmphdr *icmp_hdr = (struct icmphdr *) (new_packet + sizeof(struct ether_header) + sizeof(struct iphdr));
	icmp_hdr->code = 0;
	icmp_hdr->type = data->icmp_errortype;
	icmp_hdr->checksum = 0;
	char *icmp_payload = ((char *) icmp_hdr) + 8;
	memcpy(icmp_payload, data->buf + sizeof(struct ether_header), sizeof(struct iphdr) + 8);

	uint16_t new_icmp_checksum = checksum((uint16_t *) icmp_hdr, ntohs(new_ip_hdr->tot_len) - sizeof(struct iphdr));
	icmp_hdr->checksum = htons(new_icmp_checksum);

	send_to_link(data->recv_interface, new_packet, sizeof(struct ether_header) + 2 * sizeof(struct iphdr) + 16);

	memset(data->buf, 0, MAX_PACKET_LEN);
	return STATE_RECVEIVE;
}
