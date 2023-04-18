# Router-Dataplane

This is a C implementation of a router that knows how to handle IPv4, ARP and ICMP packets.

The packet routing process uses a very efficient algorithm to find the Longest Prefix Match in a routing table. 
Using a Trie data structure the search time depends only on the length of the searched key and not on the size of the data set. 
Basically, it needs a maximum of 32 steps to find the IPv4 address of the next hop in the path of a packet.

My router also knows how to generate and respond to ARP requests but it also knows how to generate Time Exceeded or Destination Unreachable responses for ICMP packets.

The topo.py script creates a local network simulation using the mininet tool. The network is composed of 2 routers connected to each other, and each is connected to 2 hosts. You can test the implementation using ping or arping from the terminals that open when the script runs.
