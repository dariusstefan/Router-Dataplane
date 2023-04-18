#include "trie.h"

TrieNodeP newNode() {
	TrieNodeP new_node = (TrieNodeP) malloc(sizeof(TrieNode));
	DIE(new_node == NULL, "new_trienode");

	new_node->ipEntry = NULL;
	new_node->oneChild = NULL;
	new_node->zeroChild = NULL;

	return new_node;
}

TrieP newTrie() {
	TrieP new_trie = (TrieP) malloc(sizeof(Trie));
	DIE(new_trie == NULL, "new_trie");

	new_trie->oneRoot = NULL;
	new_trie->zeroRoot = NULL;

	return new_trie;
}

void addEntry(TrieP trie, struct route_table_entry *ipEntry) {

	uint32_t prefix = ntohl(ipEntry->prefix);
	uint32_t mask = ipEntry->mask;

	int c = 0;
	while (mask != 0) {
		mask = mask & (mask - 1);
		c++;
	}

	uint32_t first_bit_mask = 1 << 31;

	TrieNodeP current_node = NULL, parent_node = NULL;

	if ((prefix & first_bit_mask) == first_bit_mask)
		current_node = trie->oneRoot;
	else
		current_node = trie->zeroRoot;

	while (current_node != NULL && c > 0) {
		prefix = prefix << 1;

		if ((prefix & first_bit_mask) == first_bit_mask) {
			parent_node = current_node;
			current_node = current_node->oneChild;
		} else {
			parent_node = current_node;
			current_node = current_node->zeroChild;
		}

		c--;
	}
	
	if (parent_node == NULL) {
		if ((prefix & first_bit_mask) == first_bit_mask) {
			trie->oneRoot = newNode();
			parent_node = trie->oneRoot;
		} else {
			trie->zeroRoot = newNode();
			parent_node = trie->zeroRoot;
		}

		prefix = prefix << 1;
		c--;
	}

	while (c > 0) {
		if ((prefix & first_bit_mask) == first_bit_mask) {
			parent_node->oneChild = newNode();
			parent_node = parent_node->oneChild;
		} else {
			parent_node->zeroChild = newNode();
			parent_node = parent_node->zeroChild;
		}

		prefix = prefix << 1;
		c--;
	}

	parent_node->ipEntry = ipEntry;
}

void completeTrie(TrieP trie, struct route_table_entry *route_table, uint32_t route_table_size) {
	for (int i = 0; i < route_table_size; i++) {
		addEntry(trie, &(route_table[i]));
	}
}
