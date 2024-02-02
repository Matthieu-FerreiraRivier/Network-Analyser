#pragma once

#include <sys/types.h>

void smtpRequest(const u_char *packet, long unsigned int size, int verbose);
void smtpReply(const u_char *packet, long unsigned int size, int verbose);