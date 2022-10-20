#include <queue.h>
#include "skel.h"
#include <header.h>


int main(int argc, char *argv[])
{
	arp_table_len = 0;
	arp_table = malloc(10 * sizeof(struct arp_entry));

	queue waitingQueue = queue_create();
	int size_rt = getRouteTable(&rtable, argv[1]); //sortat in functie	
	struct route_table_entry* route;
	packet m;
	int rc;

	setvbuf(stdout, NULL, _IONBF, 0);
	init(argc - 2, argv + 2);

	while (1) {
		//1. Primeste un pachet de la oricare din interfetele adiacente.
		rc = get_packet(&m);
		DIE(rc < 0, "get_message");
		/* Students will write code here */

		struct ether_header *eth_hdr = (struct ether_header *)m.payload;
		struct iphdr *ip_hdr = (struct iphdr *)(m.payload + sizeof(struct ether_header));

		in_addr_t interface_ip = inet_addr(get_interface_ip(m.interface));

		//2. Daca este un pachet IP destinat routerului, raspunde doar in cazul in care 
		//acesta este un pachet ICMP ECHO request. Arunca pachetul original.
		struct icmphdr *icmp_h = parse_icmp(m.payload);

		if (interface_ip == ip_hdr->daddr) { //pachet destinat routerului
			if(icmp_h != NULL) {			// de tip ICMP
				if(icmp_h->type == ICMP_ECHO){//ECHO -> trimit ECHO REPLY
						send_icmp(ip_hdr->saddr, ip_hdr->daddr,
						 eth_hdr->ether_dhost, eth_hdr->ether_shost,
						 ICMP_ECHOREPLY, 0, m.interface, 0, 0);

						continue;
				}
			}
		} 
		
		//3. Dace este un pachet ARP Request catre un IP al routerului, raspunde cu ARP Reply 
		// cu adresa MAC potrivita
		struct arp_header *arp_hdr = parse_arp(m.payload);
		if (arp_hdr != NULL) {
			if (ntohs(arp_hdr->op) == ARPOP_REQUEST) {
				//pachet ARP de tip ARP Request -> trimit ARP Reply
				memcpy(eth_hdr->ether_dhost, arp_hdr->sha, sizeof(eth_hdr->ether_dhost));
				get_interface_mac(m.interface, eth_hdr->ether_shost);

				send_arp(arp_hdr->spa, inet_addr(get_interface_ip(m.interface)), 
				eth_hdr, m.interface, htons(ARPOP_REPLY));

				continue;
			}


			//4. Daca este un pachet ARP Reply, updateaza tabela ARP; daca exista pachete ce trebuie 
			//dirijate catre acel router, transmite-le acum.
			if (ntohs(arp_hdr->op) == ARPOP_REPLY) {
				//pachet ARP de tip Reply

				struct arp_entry* arp_entry = malloc(sizeof(arp_entry));
				arp_entry->ip = arp_hdr->spa;
				memcpy(arp_entry->mac, arp_hdr->sha, sizeof(arp_hdr->sha));

				if(!arp_table_contains(arp_table, *arp_entry)) {
					arp_table[arp_table_len++] = *arp_entry;
				}

				if (!queue_empty(waitingQueue)) {
					// daca coada nu e goala -> trimit pachetul ce se afla in coada pe ruta primita
					packet* msg = (packet *)queue_deq(waitingQueue);
					struct ether_header *eth_hdr_msg = (struct ether_header *)msg->payload;

					memcpy(eth_hdr_msg->ether_dhost, arp_hdr->sha, sizeof(arp_hdr->sha));
					get_interface_mac(msg->interface, eth_hdr->ether_shost);
					send_packet(msg->interface, msg);
				}

				

				
				continue;
			}
		}

		//5. Daca este un pachet cu TTL <= 1 trimite un mesaj ICMP corect sursei (vezi mai jos); arunca pachetul.
		if (ip_hdr->ttl <= 1) {
			send_icmp_error(ip_hdr->saddr, interface_ip,
			 eth_hdr->ether_dhost, eth_hdr->ether_shost,
			 ICMP_TIME_EXCEEDED, 0, m.interface);

			continue;
		}

		//6. Daca este un pachet cu checksum gresit, arunca pachetul.
		if (ip_checksum(ip_hdr, sizeof(struct iphdr)) != 0) {
			continue;
		}

		//7. Decrementeaza TTL, updateaza.
		ip_hdr->ttl--;
		ip_hdr->check = 0;
		ip_hdr->check = ip_checksum(ip_hdr, sizeof(struct iphdr));

		//8. Cauta intrarea cea mai specifica din tabela de rutare (numita f) astfel incat (iph− >
		//daddr&f.mask == f.pref ix). Odata identificata, aceasta specifica next hop pentru pa-
		//chet. In cazul in care nu se gaseste o ruta, se trimite un mesaj ICMP sursei; arunca pachetul

		route = findBestRoute(rtable, 0, size_rt - 1, ip_hdr->daddr);

		if (route == NULL) {
			fprintf(stderr, "ruta NULLA -> DEST UNREACHABLE\n");
			send_icmp_error(ip_hdr->saddr, interface_ip,
			eth_hdr->ether_dhost, eth_hdr->ether_shost,
			ICMP_DEST_UNREACH, 0, m.interface);

			continue;
		}

		//9. Modifica adresele source si destination MAC. Daca adresa MAC nu este cunoscuta local,
		//genereaza un ARP request si transmite pe interfata destinatie. Salveaza pachetul in coada
		//pentru transmitere. atunci cand adresa MAC este cunoscuta (pasul 4).
		if (route != NULL) {
			//daca ruta este nenulla -> caut in tabela arp
			struct arp_entry* arp_entry = get_arp_entry(route->next_hop);
			if (arp_entry == NULL) {
				//adresa MAC nu este cunoscuta local -> pun in coada pachetul si trimit  ARP Request pe broadcast
				m.interface = route->interface;
				packet in_wait_pack;

				memcpy(&in_wait_pack, &m, sizeof(packet));
				queue_enq(waitingQueue, &in_wait_pack);

				struct ether_header new_eth_hdr;								
				new_eth_hdr.ether_type = htons(0x0806);
				hwaddr_aton("ff:ff:ff:ff:ff:ff", new_eth_hdr.ether_dhost);
				get_interface_mac(route->interface, new_eth_hdr.ether_shost);

				send_arp(route->next_hop,inet_addr(get_interface_ip(route->interface)),
				&new_eth_hdr, route->interface, htons(ARPOP_REQUEST));

				continue;
			}
			
			//10.Trimite pachetul mai departe folosind functia send_packet(...).
			//Procesul se reia pe următorul router până când pachetul ajunge la destinatie.
			memcpy(eth_hdr->ether_dhost, arp_entry->mac, sizeof(arp_entry->mac));
			get_interface_mac(route->interface, eth_hdr->ether_shost);
			send_packet(route->interface,&m);

			continue;
		}
	}
}
