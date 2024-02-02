#pragma once

#include <sys/types.h>

void ftpRequest(const u_char *packet, long unsigned int size, int verbose);
void ftpReply(const u_char *packet, long unsigned int size, int verbose);
void ftpData(const u_char *packet, long unsigned int size, int verbose);