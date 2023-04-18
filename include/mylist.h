#ifndef _MY_LIST_H_
#define _MY_LIST_H_

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "lib.h"

typedef struct ListNode *ListP;

struct ListNode
{
  struct route_table_entry *lpm_entry;
  char *buf;
  int len;
  ListP next;
};

ListP addNode(struct route_table_entry *lpm_entry, char *buf, ListP list, int len);
ListP searchNode(uint32_t ip, ListP *list);

#endif /* _MY_LIST_H_ */
