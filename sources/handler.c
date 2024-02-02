#include "handler.h"
#include "verbose.h"
#include "ether.h"
#include "ip.h"
#include "ipv6.h"
#include "transport.h"
#include "http.h"
#include "smtp.h"
#include "pop.h"
#include "imap.h"
#include "ftp.h"
#include "dhcp.h"
#include "dns.h"

#define CHK(op) do { if ((op) == NULL){\
printf("Format invalide, arret de l'analyse de la trame.\n");\
printf("-----------------------------------------------\n");\
return;}} while (0)

#define TCPPORT_HTTP 80
#define TCPPORT_SMTP 25
#define TCPPORT_POP 110
#define TCPPORT_IMAP 143
#define TCPPORT_FTP 21
#define TCPPORT_FTP_DATA 20
#define UDPPORT_DNS 53
#define UDPPORT_BOOTPS 67
#define UDPPORT_BOOTPC 68


void parseTcpData(const u_char *packet, struct tcphdr *tcpHeader, long unsigned int size, int verbose){
    //No data
    if(size == 0)
        return;
    
    //HTTP request
    if(ntohs(tcpHeader->dest) == TCPPORT_HTTP)
        httpRequest(packet, size, verbose);
    //HTTP reply
    else if(ntohs(tcpHeader->source) == TCPPORT_HTTP)
        httpReply(packet, size, verbose);
    //SMTP request
    else if(ntohs(tcpHeader->dest) == TCPPORT_SMTP)
        smtpRequest(packet, size, verbose);
    //SMTP reply
    else if(ntohs(tcpHeader->source) == TCPPORT_SMTP)
        smtpReply(packet, size, verbose);
    //POP request
    else if(ntohs(tcpHeader->dest) == TCPPORT_POP)
        popRequest(packet, size, verbose);
    //POP reply
    else if(ntohs(tcpHeader->source) == TCPPORT_POP)
        popReply(packet, size, verbose);
    //IMAP message
    else if(ntohs(tcpHeader->dest) == TCPPORT_IMAP || ntohs(tcpHeader->source) == TCPPORT_IMAP)
        imapMessage(packet, size, verbose);
    //FTP request
    else if(ntohs(tcpHeader->dest) == TCPPORT_FTP)
        ftpRequest(packet, size, verbose);
    //FTP reply
    else if(ntohs(tcpHeader->source) == TCPPORT_FTP)
        ftpReply(packet, size, verbose);
    //FTP data transfert
    else if(ntohs(tcpHeader->dest) == TCPPORT_FTP_DATA || tcpHeader->source == TCPPORT_FTP_DATA)
        ftpData(packet, size, verbose);
    
    return;
}

void parseUdpData(const u_char *packet, struct udphdr *udpHeader, long unsigned int size, int verbose){
    //No data
    if(size == 0)
        return;

    //DNS message
    if(ntohs(udpHeader->dest) == UDPPORT_DNS || ntohs(udpHeader->source) == UDPPORT_DNS)
        dnsMessage(packet, size, verbose);
    //DHCP message
    else if((ntohs(udpHeader->dest) == UDPPORT_BOOTPS && ntohs(udpHeader->source) == UDPPORT_BOOTPC)
         || (ntohs(udpHeader->dest) == UDPPORT_BOOTPC && ntohs(udpHeader->source) == UDPPORT_BOOTPS))
        dhcpMessage(packet, size, verbose);

    return;
}



void handler(u_char *args, const struct pcap_pkthdr* header, const u_char *packet){
    int verbose = ((struct handler_args *)args)->verbose;
    //check if packet is truncated
    if(header->caplen < header->len){
        printf("Paquet tronqué, analyse impossible.\n");
        printf("-----------------------------------------------\n");
        return;
    }
    //remaining size of packet
    long unsigned int remaining = header->caplen;


ethernet:
    struct ether_header * eternetHeader;
    CHK(packet = uncaps_ether(packet, &eternetHeader, &remaining, verbose));

    switch(ntohs(eternetHeader->ether_type)){
        case ETHERTYPE_IP:
            goto ip;
        case ETHERTYPE_IPV6:
            goto ipv6;
        case ETHERTYPE_ARP:
            if(verbose == VERBOSE_LOW)
                printf("/");
            CHK(uncaps_arp(packet, NULL, &remaining, verbose));
            goto end;
        default:
            goto end;
    }

ip:
   struct iphdr *ipHeader;
    if(verbose == VERBOSE_LOW)
        printf("/");
    CHK(packet = uncaps_ip(packet, &ipHeader, &remaining, verbose));

    switch(ipHeader->protocol){
        case IPPROTO_TCP:
            goto tcp;
        case IPPROTO_UDP:
            goto udp;
        case IPPROTO_IP:
            goto ip;
        case IPPROTO_IPV6:
            goto ipv6;
        case IPPROTO_ETHERNET:
            goto ethernet;
        case IPPROTO_ICMP:
            if(verbose == VERBOSE_LOW)
                printf("/");
            CHK(uncaps_icmp(packet, NULL, &remaining, verbose));
            goto end;
        default:
            goto end;
    }

ipv6:
    struct ip6_hdr *ip6Header;
    uint8_t ul;
    if(verbose == VERBOSE_LOW)
        printf("/");
    CHK(packet = uncaps_ipv6(packet, &ip6Header, &ul, &remaining, verbose));

    switch(ul){
        case IPPROTO_TCP:
            goto tcp;
        case IPPROTO_UDP:
            goto udp;
        case IPPROTO_IP:
            goto ip;
        case IPPROTO_IPV6:
            goto ipv6;
        case IPPROTO_ETHERNET:
            goto ethernet;
        case IPPROTO_ICMPV6:
            if(verbose == VERBOSE_LOW)
                printf("/");
            CHK(uncaps_icmpv6(packet, NULL, &remaining, verbose));
            goto end;
        default:
            goto end;
    }

tcp:
    struct tcphdr *tcpHeader;
    if(verbose == VERBOSE_LOW)
        printf("/");
    CHK(packet = uncaps_tcp(packet, &tcpHeader, &remaining, verbose));
    if(verbose == VERBOSE_LOW)
        printf("/");
    parseTcpData(packet, tcpHeader, remaining, verbose);
    goto end;

udp:
    struct udphdr *udpHeader;
    if(verbose == VERBOSE_LOW)
        printf("/");
    CHK(packet = uncaps_udp(packet, &udpHeader, &remaining, verbose));
    if(verbose == VERBOSE_LOW)
        printf("/");
    parseUdpData(packet, udpHeader, remaining, verbose);
    goto end;


end:
    if(verbose == VERBOSE_LOW)
        printf("\n");
    printf("-----------------------------------------------\n");
    return;
}