#include <arpa/inet.h>
#include "queue.h"
#include "lib.h"
#include "protocols.h"

//  Routing tables
struct route_table_entry *rtable;
int rtable_len;

//  Mac table
struct arp_table_entry *arp_table;
int arp_table_len;

//  Trie
struct Trie *trie;

//  Returns a pointer to the best matching route, or NULL if there is none
struct route_table_entry *get_best_route(uint32_t ip_dest) {
	int i, index = -1;

	for(i = 0; i < rtable_len; i++){
		if((ip_dest & rtable[i].mask) == rtable[i].prefix 
			&& rtable[i].mask > rtable[index].mask) {
			index = i;
		}
	}

	if (index == -1) {
		return NULL;
	}

	return &rtable[index];
}

struct route_table_entry *get_best_route_trie(uint32_t ip_dest, struct Node *root,
												int level) {
	//  Parse the trie on corresponding IP bits
	if (root->isLeaf == 0) {
		//  If a path is not found, we return NULL
		if (root->children[(ip_dest >> level) & 1] == NULL) {
			return NULL;
		} else {
			return get_best_route_trie(ip_dest, root->children[(ip_dest >> level) & 1],
							level + 1);
		}
	}

	return root->route;
}

struct arp_table_entry *get_arp_table_entry(uint32_t given_ip) {
	//  Iterate through the arp_table
	for (int i = 0; i < arp_table_len; i++) {
		if(arp_table[i].ip == given_ip) {
			return &arp_table[i];
		}
	}

	return NULL;
}

int main(int argc, char *argv[]) {
	char buf[MAX_PACKET_LEN];

	// Do not modify this line
	init(argc - 2, argv + 2);

	//  Alloc rtable and arp_table
	rtable = malloc(sizeof(struct route_table_entry) * 80000);
	DIE(rtable == NULL, "rtable");

	arp_table = malloc(sizeof(struct  arp_table_entry) * 100);
	DIE(arp_table == NULL, "arp_table");
	
	rtable_len = read_rtable(argv[1], rtable);
	arp_table_len = parse_arp_table("arp_table.txt", arp_table);

	//  Alloc and populate trie
	trie = createTrie(rtable, rtable_len);

	while (1) {
		int interface;
		size_t len;

		interface = recv_from_any_link(buf, &len);
		DIE(interface < 0, "recv_from_any_link");

		struct ether_header *eth_hdr = (struct ether_header *) buf;
		struct iphdr *ip_hdr = (struct iphdr *)(buf + sizeof(struct ether_header));

		//  Check if we got an IPv4 packet
		if (eth_hdr->ether_type != ntohs(ETHERTYPE_IP)) {
			continue;
		}

		//  Verify checksum
		uint16_t buf_checksum = ntohs(ip_hdr->check);
		ip_hdr->check = 0;

		if(buf_checksum != checksum((uint16_t *)ip_hdr, sizeof(struct iphdr))) {
			continue;
		}

		ip_hdr->check = htons(buf_checksum);

		//  Check TTL
		if (ip_hdr->ttl == 0) {
			continue;
		}

		//  Using get_best_route to find the most specific route, if there is one
		//  This is the linear implementation
		//  struct route_table_entry *best_route = get_best_route(ip_hdr->daddr);

		//  Using trie to find the most specific route, if there is one
		struct route_table_entry *best_route = get_best_route_trie(ip_hdr->daddr, 
												trie->root, MSB);

		if (best_route == NULL) {
			continue;
		}

		//  Update TLL. Update checksum
		ip_hdr->ttl--;
		ip_hdr->check = ~(~ip_hdr->check + ~((uint16_t)ip_hdr->ttl + 1) + (uint16_t)ip_hdr->ttl) - 1;

		//  Update the ethernet addresses.
		uint8_t smac[6];
		struct arp_table_entry *dest_arp_table_entry = get_arp_table_entry(best_route->next_hop);

		if (dest_arp_table_entry == NULL) {
			continue;
		}

		get_interface_mac(best_route->interface, smac);

		for (int i = 0; i < 6; i++){
			eth_hdr->ether_dhost[i] = dest_arp_table_entry->mac[i];
			eth_hdr->ether_shost[i] = smac[i];
		}
		
		//  Send buf	  
		send_to_link(best_route->interface, buf, len);

		/* Note that packets received are in network order,
		any header field which has more than 1 byte will need to be converted to
		host order. For example, ntohs(eth_hdr->ether_type). The oposite is needed when
		sending a packet on the link, */
	}

	//  Free all
	destroyTrie(&trie);
	free(rtable);
	free(arp_table);
}

