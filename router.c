#include "state.h"

int main(int argc, char *argv[])
{
	char buf[MAX_PACKET_LEN];

	init(argc - 2, argv + 2);

	state_t cur_state = STATE_INITIAL;

	instance_data data;
	data.route_table = (struct route_table_entry *) malloc(sizeof(struct route_table_entry) * 80000);
	DIE(data.route_table == NULL, "rtable alloc");

	data.arp_table = (struct arp_entry *) malloc(sizeof(struct arp_entry) * 20);

	data.rtable_path = argv[1];
	data.buf = buf;

	data.list = NULL;
	data.icmp_errortype = 0;

	while (1) {
		cur_state = run_state(cur_state, &data);
	}

	return 0;
}
