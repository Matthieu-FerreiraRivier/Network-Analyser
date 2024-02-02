#pragma once

#include <sys/types.h>

void httpRequest(const u_char *packet, long unsigned int size, int verbose);
void httpReply(const u_char *packet, long unsigned int size, int verbose);