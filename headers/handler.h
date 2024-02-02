#pragma once

#include<stdio.h>
#include<sys/types.h>
#include<pcap.h>


struct handler_args{
    int verbose;
};

void handler(u_char *args, const struct pcap_pkthdr* header, const u_char *packet);