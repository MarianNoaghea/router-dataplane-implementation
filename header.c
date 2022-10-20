#include "header.h"

int getRouteTable(struct route_table_entry** route_table, char *path) {
	FILE *rt;
	char * line = NULL;
    size_t len = 0;
    ssize_t read;
	int table_len = 0, alocated_len = 100;
	*route_table = malloc(sizeof(struct route_table_entry) * 100);

	rt = fopen(path, "r");
	if(!rt)
		exit(EXIT_FAILURE);
	
	while ((read = getline(&line, &len, rt)) != -1) {
		struct route_table_entry entry;

		int col = 0;

		struct in_addr a;

        for (char *p = strtok(line, " "); p != NULL; p = strtok(NULL, " ")) {
			switch(col)
			{
				case 0:
					inet_aton(p, &a);
					entry.prefix = a.s_addr;
					break;
				case 1:
					inet_aton(p, &a);
					entry.next_hop = a.s_addr;
					break;
				case 2:
					inet_aton(p, &a);
					entry.mask = a.s_addr;
					break;
				case 3:
					entry.interface = atoi(p);
					break;
				default:
						break;
			}

			col++;
        }

		(*route_table)[table_len++] = entry;

		if(table_len + 100 >= alocated_len) {
			*route_table = (struct route_table_entry*)realloc(*route_table, sizeof(entry)*(table_len + 100));
			alocated_len += 100;
		}
	}

	qsort(*route_table, table_len, sizeof(struct route_table_entry), cmpfunc);
	

	return table_len;
}

int cmpfunc(const void * a, const void * b){
    struct route_table_entry* pA = (struct route_table_entry*)a;
    struct route_table_entry* pB = (struct route_table_entry*)b;

    uint32_t prefix1 = pA->prefix;
    uint32_t prefix2 = pB->prefix;
	uint32_t mask1 = pA->mask;
	uint32_t mask2 = pB->mask;

	int diff = ntohl(prefix1) - ntohl(prefix2);
    
    if (diff == 0) {
        return mask2 - mask1;
    }

	return diff;
}

struct route_table_entry* findBestRoute(struct route_table_entry *arr, int l, int r, __uint32_t dest_ip)
    {
		int index = -1, mid, dif;

        while (l <= r) {
			mid = r + (l - r) / 2;

			dif = ntohl(arr[mid].mask & dest_ip) - ntohl(arr[mid].prefix);
			if (dif == 0) {
				if (index == -1 || ntohl(arr[mid].mask) > ntohl(arr[index].mask)) {
					index = mid;
				}
					
			}

			if(dif < 0) {
				r = mid - 1;
			} else {
				l = mid + 1;
			}
		}

		if(index == -1) {
			return NULL;
		}
  
        return &arr[index];
}

void print_mac_string(uint8_t *mac) {
	for(int i = 0; i < 6; i++) {
		fprintf(stderr, "%x", mac[i]);
	}
}

struct arp_entry *get_arp_entry(__u32 ip) {
    struct arp_entry *point = arp_table;
 
    for (int i = 0; i < arp_table_len; i++) {
        if (ntohl(point[i].ip) ==ntohl(ip)) {
            return &point[i];
        }
    }
 
    return NULL;
}

int arp_table_contains(struct arp_entry* arp_table,struct arp_entry arp_entry) {

	for(int i = 0; i < arp_table_len; i++) {
		if(ntohl(arp_table[i].ip) == ntohl(arp_entry.ip))
			return 1;
	}

	return 0;
}
