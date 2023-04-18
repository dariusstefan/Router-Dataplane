#include "mylist.h"

ListP addNode(struct route_table_entry *lpm_entry, char *buf, ListP list, int len) {
	ListP newNode = (ListP) malloc(sizeof(struct ListNode));
	DIE(newNode == NULL, "new list node");

	newNode->buf = (char *) malloc(MAX_PACKET_LEN);
	DIE(newNode->buf == NULL, "new buf");

	memcpy(newNode->buf, buf, MAX_PACKET_LEN);

	newNode->lpm_entry = lpm_entry;

	newNode->next = list;

	newNode->len = len;
	
	return newNode;
}

ListP searchNode(uint32_t ip, ListP *list) {
	ListP current = *list, prev = NULL, found = NULL;

	while (current != NULL) {
		if (current->lpm_entry->next_hop == ip) {
			found = current;
			break;
		}
		prev = current;
		current = current->next;
	}

	if (prev != NULL && found != NULL) {
		prev->next = current->next;
	}
	
	if (prev == NULL && found != NULL) {
		*list = NULL;
	}

	return found;
}
