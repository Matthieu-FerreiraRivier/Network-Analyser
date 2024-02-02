#pragma once

#include <netinet/udp.h>
#include <netinet/tcp.h>

const u_char *uncaps_udp(const u_char *packet, struct udphdr **head, long unsigned int *size, int verbose);
const u_char *uncaps_tcp(const u_char *packet, struct tcphdr **head, long unsigned int *size, int verbose);