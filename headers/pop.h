#pragma once

#include <sys/types.h>

void popRequest(const u_char *packet, long unsigned int size, int verbose);
void popReply(const u_char *packet, long unsigned int size, int verbose);
