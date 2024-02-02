#pragma once

#include <netinet/ip.h>
#include <netinet/ip_icmp.h>



const u_char *uncaps_ip(const u_char *packet, struct iphdr **head, long unsigned int *size, int verbose);
const u_char *uncaps_icmp(const u_char *packet, struct icmphdr **head, long unsigned int *size, int verbose);