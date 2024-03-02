#include "queue.h"
#include "lib.h"
#include "protocols.h"
#include <arpa/inet.h>
#include <string.h>
//functie de a calcula cea mai buna ruta
struct route_table_entry* get_best_route(struct route_table_entry *rtable, int rtable_size, uint32_t dest_ip) {
	struct route_table_entry *best_route = NULL;
	for (int i = 0; i < rtable_size; i++) { //parcurgem tabela de rutare
		if ((dest_ip & rtable[i].mask) == (rtable[i].prefix & rtable[i].mask)) { //verificam daca prefixul din tabela de rutare se potriveste cu adresa ip
			if (best_route == NULL) {
				best_route = &rtable[i];
			} else { //daca exista deja o ruta, verificam daca masca este mai mare
				if (best_route->mask < rtable[i].mask) {
					best_route = &rtable[i];
				}
			}
		}
	}
	return best_route;
}
int main(int argc, char *argv[])
{
	char buf[MAX_PACKET_LEN];

	// Do not modify this line
	init(argc - 2, argv + 2);

	struct route_table_entry *rtable = malloc(100000 * sizeof(struct route_table_entry)); //alocam memorie pentru tabela de rutare
	int rtable_size = read_rtable(argv[1], rtable); //citim tabela de rutare din fisier

	struct arp_entry* arp_entry = malloc(10 * sizeof(struct arp_entry)); //alocam memorie pentru tabela arp
	int arp_entry_size = parse_arp_table("arp_table.txt", arp_entry); //citim tabela arp din fisier

	while (1) {

		int interface;
		size_t len;

		interface = recv_from_any_link(buf, &len);
		DIE(interface < 0, "recv_from_any_links");

		struct ether_header *eth_hdr = (struct ether_header *) buf;
		struct iphdr *ip_hdr = (struct iphdr *) (buf + sizeof(struct ether_header));

		/* Note that packets received are in network order,
		any header field which has more than 1 byte will need to be conerted to
		host order. For example, ntohs(eth_hdr->ether_type). The oposite is needed when
		sending a packet on the link, */
		uint16_t ether_type = ntohs(eth_hdr->ether_type); 
		// verificare ca adresa mac destinatie este adresa routerului
		uint8_t *mac = malloc(6);
		get_interface_mac(interface, mac); //iau adresa mac a interfetei pe care am primit pachetul
		if(memcmp(eth_hdr->ether_dhost, mac, 6) != 0) { 
			continue;
		}
		if(ether_type != 0x0800) {
			continue; 
		}
		//pana aici e partea de dirijare a pachetelor 

		//verificare checksum
		uint16_t checksumold = ip_hdr->check;
		ip_hdr->check = 0;
		uint16_t new_checksum = htons(checksum((uint16_t *) ip_hdr, sizeof(struct iphdr)));
		if(checksumold != new_checksum) {
			continue;
		}
		// verificare TTL
		if(ip_hdr->ttl <= 1) {
			continue;
		}
		// decrementare TTL
		ip_hdr->ttl--;
		// recalculare checksum
		ip_hdr->check = 0;
		ip_hdr->check = htons(checksum((uint16_t *) ip_hdr, sizeof(struct iphdr)));
	
		// find best route
		struct route_table_entry *best_route = get_best_route(rtable, rtable_size, ip_hdr->daddr);
		// verificare daca exista ruta
		if (best_route == NULL) {
			continue;
		}
		// verificare daca e broadcast
		if(best_route->next_hop == 0) {
			//best_route->next_hop = ip_hdr->daddr;
			continue;
		}
		// modificare adresa mac sursa
		uint8_t *mac_source = malloc(6);
		get_interface_mac(best_route->interface, mac_source);
		memcpy(eth_hdr->ether_shost, mac_source, 6);
		// modificare adresa mac destinatie
		int i;
		uint8_t *mac_dest = malloc(6);
		for(i = 0; i < arp_entry_size; i++) {
			if(arp_entry[i].ip == best_route->next_hop) {
				memcpy(mac_dest, arp_entry[i].mac, 6);
				break;
			}
		}
		memcpy(eth_hdr->ether_dhost, mac_dest, 6);
		// trimitere pachet
		send_to_link(best_route->interface, buf, len);
	}
}