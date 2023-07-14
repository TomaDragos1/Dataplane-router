#include "queue.h"
#include "lib.h"
#include "protocols.h"
#include <unistd.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <linux/if_arp.h>
#include <string.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <linux/if_arp.h>
#include <string.h>

struct route_table_entry *route_entry;
uint16_t route_entry_lenght;

struct arp_entry *arp_table;
int arp_table_len = 0;


struct TrieNode
{
	struct route_table_entry *entry;
	struct TrieNode *left;
	struct TrieNode *right;
};


struct ipv4_packet
{
	char buffer[MAX_PACKET_LEN];
	int lenght;
	int interface;
	uint32_t ip_next_hop;
};

void insert_route_entry(struct TrieNode *root, struct route_table_entry *entry)
{
	int prefix_length = 0;
	uint32_t mask = ntohl(entry->mask);
	uint32_t and = 1 << 31;

	// make the mask in int
	while (mask & (1 << 31))
	{
		prefix_length++;
		mask <<= 1;
	}
	uint32_t prefix = ntohl(entry->prefix);
	struct TrieNode *node = root;

	// just insert the current entrie

	for (int i = 0; i < prefix_length; i++)
	{
		uint32_t bit = (prefix << i) & and;

		if (bit == 0)
		{
			if (node->left == NULL)
			{
				struct TrieNode *new_node = (struct TrieNode *)calloc(1, sizeof(struct TrieNode));
				node->left = new_node;
				node = node->left;
			}
			else
			{
				node = node->left;
			}
		}
		else
		{
			if (node->right == NULL)
			{
				struct TrieNode *new_node = (struct TrieNode *)calloc(1, sizeof(struct TrieNode));
				node->right = new_node;
				node = node->right;
			}
			else
			{
				node = node->right;
			}
		}
	}

	node->entry = entry;
}

// search in the trie

struct route_table_entry *get_route_trie(uint32_t ip, struct TrieNode *root)
{
	struct TrieNode *node = root;
	struct route_table_entry *entry = NULL;
	while (node != NULL)
	{
		if (node->entry != NULL)
		{
			entry = node->entry;
		}

		uint32_t bit = (ip >> 31) & 1;
		ip <<= 1;

		if (bit == 0)
		{
			node = node->left;
		}
		else
		{
			node = node->right;
		}
	}
	return entry;
}

// search the current ip the the table

struct arp_entry *get_arp_entry(uint32_t ip_dest)
{

	for (int i = 0; i < arp_table_len; i++)
	{
		if (ip_dest == arp_table[i].ip)
		{
			return &arp_table[i];
		}
	}
	return NULL;
}

// send the arp request

void send_arp_request(int interface, uint32_t dest)
{

	int size = sizeof(struct ether_header) + sizeof(struct arp_header);
	struct ether_header *eth = malloc(sizeof(struct ether_header));
	struct arp_header *arp = malloc(sizeof(struct arp_header));

	eth->ether_type = ntohs(0x0806);

	// construct the arp req structure
	// construct with my mac, ip and the dest ip is 0.0.0. and mac is the boradcast

	arp->htype = htons(ARPHRD_ETHER);
	arp->ptype = htons(ETH_P_IP);
	arp->hlen = 6;
	arp->plen = 4;
	arp->op = htons(1);
	u_int8_t mac[6];
	get_interface_mac(interface, mac);
	memcpy(arp->sha, mac, 6);
	memcpy(eth->ether_shost, mac, 6);
	arp->spa = (inet_addr(get_interface_ip(interface)));
	memcpy(arp->tha, "\x00\x00\x00\x00\x00\x00", 6);
	memcpy(eth->ether_dhost, "\xff\xff\xff\xff\xff\xff", 6);
	arp->tpa = dest;

	// put them in a packet and then send

	char buf[size];
	memcpy(buf, eth, sizeof(struct ether_header));
	memcpy(buf + sizeof(struct ether_header), arp, sizeof(struct arp_header));
	send_to_link(interface, buf, size);

	free(arp);
	free(eth);
}

void send_arp_reply(int my_interface, struct arp_header *old_arp)
{
	int size = sizeof(struct ether_header) + sizeof(struct arp_header);
	struct ether_header *eth = malloc(sizeof(struct ether_header));
	struct arp_header *arp = malloc(sizeof(struct arp_header));

	eth->ether_type = ntohs(0x0806);
	// construct the arp reply with the
	// mac and ip of the sorce
	arp->htype = htons(ARPHRD_ETHER);
	arp->ptype = htons(ETH_P_IP);
	arp->hlen = 6;
	arp->plen = 4;
	arp->op = htons(2);
	u_int8_t mac[6];
	get_interface_mac(my_interface, mac);
	memcpy(eth->ether_shost, mac, 6);
	memcpy(eth->ether_dhost, old_arp->sha, 6);
	memcpy(arp->sha, mac, 6);
	memcpy(arp->tha, old_arp->sha, 6);

	arp->spa = (inet_addr(get_interface_ip(my_interface)));
	arp->tpa = old_arp->spa;

	char buf[size];
	memcpy(buf, eth, sizeof(struct ether_header));
	memcpy(buf + sizeof(struct ether_header), arp, sizeof(struct arp_header));

	send_to_link(my_interface, buf, size);

	free(arp);
	free(eth);
}

// populate the structure of ip for the icmp send

struct iphdr *creat_iph(uint32_t source, uint32_t dest)
{
	struct iphdr *new_ip_hdr = malloc(sizeof(struct iphdr));
	new_ip_hdr->version = 4;
	new_ip_hdr->ihl = 5;
	new_ip_hdr->tos = 0;
	new_ip_hdr->tot_len = htons(sizeof(struct iphdr) + sizeof(struct icmphdr));
	new_ip_hdr->id = htons(1);
	new_ip_hdr->frag_off = 0;
	new_ip_hdr->ttl = 64;
	new_ip_hdr->protocol = IPPROTO_ICMP;
	new_ip_hdr->saddr = source;
	new_ip_hdr->daddr = dest;
	new_ip_hdr->check = 0;
	new_ip_hdr->check = htons(checksum((uint16_t *)new_ip_hdr, sizeof(struct iphdr)));

	return new_ip_hdr;
}

// icmp reply if someone pings on router

void send_icmp_echo_reply(struct icmphdr *icmp_hdr_old, struct iphdr *ip_hdr_old, struct ether_header *eth_old, int interface, char *my_packet)
{
	struct icmphdr *new_icmp = malloc(sizeof(struct icmphdr));

	struct iphdr *ip_hdr;

	struct ether_header *eth = malloc(sizeof(struct ether_header));

	// new icmp
	new_icmp->code = 0;
	new_icmp->type = 0;
	new_icmp->checksum = 0;
	new_icmp->un.echo.id = icmp_hdr_old->un.echo.id;
	new_icmp->un.echo.sequence = icmp_hdr_old->un.echo.sequence;

	new_icmp->checksum = htons(checksum((uint16_t *)new_icmp, sizeof(struct icmphdr)));

	// construct new eth
	memcpy(eth->ether_dhost, eth_old->ether_shost, 6);
	memcpy(eth->ether_shost, eth_old->ether_dhost, 6);
	eth->ether_type = htons(2048);

	// construct new ip header
	ip_hdr = creat_iph((inet_addr(get_interface_ip(interface))), ip_hdr_old->saddr);

	int size = sizeof(struct icmphdr) + sizeof(struct iphdr) + sizeof(struct ether_header);
	char *buf = malloc(MAX_PACKET_LEN);

	memcpy(buf, eth, sizeof(struct ether_header));
	memcpy(buf + sizeof(struct ether_header), ip_hdr, sizeof(struct iphdr));
	memcpy(buf + sizeof(struct ether_header) + sizeof(struct iphdr), new_icmp, sizeof(struct icmphdr));

	send_to_link(interface, buf, size);
}

// for ttl eror icmp and the host not reacheable

void send_icmp_ttl(struct icmphdr *icmp_hdr_old, struct iphdr *ip_hdr_old, struct ether_header *eth_old, int interface, int var, char *packet)
{

	struct icmphdr *new_icmp = malloc(sizeof(struct icmphdr));

	struct ether_header *eth = malloc(sizeof(struct ether_header));

	if (var == 1)
		new_icmp->type = 11;
	else
	{
		new_icmp->type = 3;
	}

	new_icmp->code = 0;
	new_icmp->checksum = 0;
	new_icmp->checksum = ntohs(checksum((uint16_t *)new_icmp, sizeof(struct icmphdr)));

	struct iphdr *ip_hdr = creat_iph((inet_addr(get_interface_ip(interface))), ip_hdr_old->saddr);

	u_int8_t mac[6];
	get_interface_mac(interface, mac);

	memcpy(eth->ether_dhost, eth_old->ether_shost, 6);
	memcpy(eth->ether_shost, mac, 6);
	eth->ether_type = htons(2048);

	int size = sizeof(struct icmphdr) + sizeof(struct iphdr) + sizeof(struct ether_header);
	char *buf = malloc(MAX_PACKET_LEN);

	memcpy(buf, eth, sizeof(struct ether_header));
	memcpy(buf + sizeof(struct ether_header), ip_hdr, sizeof(struct iphdr));
	memcpy(buf + sizeof(struct ether_header) + sizeof(struct iphdr), new_icmp, sizeof(struct icmphdr));

	memcpy(buf + size, ip_hdr_old, sizeof(struct iphdr));
	size += sizeof(struct iphdr);
	memcpy(buf + size, packet + sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr), 8);
	size += 8;

	send_to_link(interface, buf, size);
}

int main(int argc, char *argv[])
{
	char buf[MAX_PACKET_LEN];

	// Do not modify this line
	init(argc - 2, argv + 2);
	route_entry = malloc(100000 * sizeof(struct route_table_entry));
	route_entry_lenght = read_rtable(argv[1], route_entry);

	queue q = queue_create();

	arp_table = malloc(100 * sizeof(struct arp_entry));

	struct TrieNode *root = (struct TrieNode *)calloc(1, sizeof(struct TrieNode));

	for (int i = 0; i < route_entry_lenght; i++)
	{
		insert_route_entry(root, &route_entry[i]);
	}

	while (1)
	{

		int interface;
		size_t len;

		interface = recv_from_any_link(buf, &len);
		DIE(interface < 0, "recv_from_any_links");

		struct ether_header *eth_hdr = (struct ether_header *)buf;
		// struct iphdr *ip_hdr = (struct iphdr *)(buf + sizeof(struct ether_header));
		/* Note that packets received are in network order,
		any header field which has more than 1 byte will need to be conerted to
		host order. For example, ntohs(eth_hdr->ether_type). The oposite is needed when
		sending a packet on the link, */

		int type = ntohs(eth_hdr->ether_type);
		if (type == 2048)
		{

			// if i get an ipv4 packet

			struct iphdr *ip_hdr = (struct iphdr *)(buf + sizeof(struct ether_header));
			uint32_t router_ip = inet_addr(get_interface_ip(interface));
			struct icmphdr *icmp_hdr = (struct icmphdr *)(buf + sizeof(struct iphdr) + sizeof(struct ether_header));
			if (router_ip == ip_hdr->daddr && (icmp_hdr->type) == 8)
			{
				// here if the ping is me i reply with an icmp
				send_icmp_echo_reply(icmp_hdr, ip_hdr, eth_hdr, interface, buf);
				continue;
			}

			uint16_t old = ntohs(ip_hdr->check);
			ip_hdr->check = 0;
			// verif the checksum
			int sum = checksum((uint16_t *)ip_hdr, sizeof(struct iphdr));
			if (sum != old)
			{
				continue;
			}

			uint8_t old_ttl = ip_hdr->ttl;

			ip_hdr->ttl--;

			// verif the ttl and send the icmp if its the case

			if (ip_hdr->ttl < 1)
			{
				send_icmp_ttl(icmp_hdr, ip_hdr, eth_hdr, interface, 1, buf);
				continue;
			}
			old = htons(old);

			// recalculate the checksum

			ip_hdr->check = ~(~old + ~((uint16_t)old_ttl) + (uint16_t)ip_hdr->ttl) - 1;

			struct route_table_entry *interface_route = get_route_trie(ntohl(ip_hdr->daddr), root);
			if (interface_route == NULL)
			{

				// host not reacheable
				send_icmp_ttl(icmp_hdr, ip_hdr, eth_hdr, interface, 0, buf);
				continue;
			}

			struct arp_entry *current_arp_entry = get_arp_entry(interface_route->next_hop);

			if (current_arp_entry == NULL)
			{

				// if the mac of the next hop is not in table then i will
				// put my paket in queue and then send a request

				struct ipv4_packet packet;
				memcpy(packet.buffer, buf, len);
				packet.lenght = len;
				packet.interface = interface_route->interface;
				packet.ip_next_hop = interface_route->next_hop;
				struct ether_header *eth_hdr_current = (struct ether_header *)buf;
				get_interface_mac(packet.interface, eth_hdr_current->ether_shost);
				queue_enq(q, &packet);
				send_arp_request(interface_route->interface, interface_route->next_hop);
			}
			else
			{

				// if not i just send the packet with the source and dest mac changed

				memcpy(eth_hdr->ether_dhost, current_arp_entry->mac, 6);
				get_interface_mac(interface_route->interface, eth_hdr->ether_shost);
				send_to_link(interface_route->interface, buf, len);
			}
		}
		else
		{
			// arp reply and request part
			struct arp_header *arp = (struct arp_header *)(buf + sizeof(struct ether_header));

			if (ntohs(arp->op) == ARPOP_REPLY)
			{
				// arp reply i put the new entry in the arp table
				struct arp_entry *new_entry = malloc(sizeof(struct arp_entry));
				new_entry->ip = arp->spa;
				memcpy(new_entry->mac, arp->sha, 6);
				arp_table[arp_table_len] = *new_entry;
				arp_table_len++;

				if (!queue_empty(q))
				{

					// send the first packet in queue
					struct ipv4_packet *current_packet = queue_deq(q);
					struct ether_header *eth_hdr_current = (struct ether_header *)current_packet->buffer;

					memcpy(eth_hdr_current->ether_dhost, new_entry->mac, 6);
					send_to_link(current_packet->interface, current_packet->buffer, current_packet->lenght);
				}
			}
			else
			{
				// if i receive a request i send a reply
				uint32_t my_ip = inet_addr(get_interface_ip(interface));
				if (my_ip == arp->tpa)
				{
					send_arp_reply(interface, arp);
				}
			}
		}
	}
}
