#pragma once

#include <netinet/ip6.h>
#include <netinet/icmp6.h>


const u_char *uncaps_ipv6(const u_char *packet, struct ip6_hdr **head, uint8_t *ul, long unsigned int *size, int verbose);
const u_char *uncaps_icmpv6(const u_char *packet, struct icmp6_hdr **head, long unsigned int *size, int verbose);