#ifndef _TRIE_H_
#define _TRIE_H_

#include <stdlib.h>
#include <stdio.h>
#include <arpa/inet.h>
#include "lib.h"

typedef struct TrieNodeS {
	struct route_table_entry *ipEntry;
	struct TrieNodeS *zeroChild;
	struct TrieNodeS *oneChild;
} TrieNode, *TrieNodeP;

typedef struct {
	TrieNodeP zeroRoot;
	TrieNodeP oneRoot;
} Trie, *TrieP;

TrieNodeP newNode();
TrieP newTrie();
void addEntry(TrieP trie, struct route_table_entry *ipEntry);
void completeTrie(TrieP trie, struct route_table_entry *route_table, uint32_t route_table_size);

#endif /* _TRIE_H_ */
