#pragma once

#include <net/ethernet.h>
#include <net/if_arp.h>

const u_char *uncaps_ether(const u_char *packet, struct ether_header **head, long unsigned int *size, int verbose);
const u_char *uncaps_arp(const u_char *packet, struct arphdr **head, long unsigned int *size, int verbose);