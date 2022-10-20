#pragma once
#include "skel.h"

struct route_table_entry *rtable;
int rtable_size;

struct arp_entry *arp_table;
int arp_table_len;

int getRouteTable(struct route_table_entry** route_table, char *path);

struct route_table_entry* findBestRoute(struct route_table_entry *arr, int l, int r, __uint32_t dest_ip);

int cmpfunc(const void * a, const void * b);

void print_mac_string(uint8_t *mac);

struct arp_entry *get_arp_entry(__u32 ip);

int arp_table_contains(struct arp_entry* arp_table,struct arp_entry arp_entry);

