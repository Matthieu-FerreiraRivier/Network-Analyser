#include "ipv6.h"
#include "verbose.h"
#include <stdio.h>
#include <arpa/inet.h>

#define VERSION_MASK 0xf0000000
#define TRAFFIC_CLASS_MASK 0x0ff00000
#define FLOW_LABEL_MASK 0x000fffff

#define IPV6_EXT_HOP 0
#define IPV6_EXT_ROUTING 43
#define IPV6_EXT_FRAGMENT 44
#define IPV6_EXT_ESP 50
#define IPV6_EXT_AUTH 51
#define IPV6_EXT_NONE 59
#define IPV6_EXT_DEST 60
#define IPV6_EXT_MOBILITY 135

void printHeaderType(uint8_t ul){
    switch(ul){
        case IPV6_EXT_HOP:
            printf("Hop-by-Hop Options Header");
            break;
        case IPV6_EXT_ROUTING:
            printf("Routing Header");
            break;
        case IPV6_EXT_FRAGMENT:
            printf("Fragment Header");
            break;
        case IPV6_EXT_ESP:
            printf("Encapsulating Security Payload Header");
            break;
        case IPV6_EXT_AUTH:
            printf("Authentication Header");
            break;
        case IPV6_EXT_DEST:
            printf("Destination Options Header");
            break;
        case IPV6_EXT_MOBILITY:
            printf("Mobility Header");
            break;
        case IPPROTO_TCP:
            printf("TCP");
            break;
        case IPPROTO_UDP:
            printf("UDP");
            break;
        case IPPROTO_IPV6:
            printf("IPv6");
            break;
        case IPPROTO_ETHERNET:
            printf("Ethernet");
            break;
        case IPPROTO_ICMPV6:
            printf("ICMPv6");
            break;
        default:
            printf("Unknown Header");
    }

}

int extentionHeader(const u_char **packet, uint8_t *ul, long unsigned int *size, int verbose){
    (void)verbose;
    
    switch(*ul){
        case IPV6_EXT_HOP:
        case IPV6_EXT_ROUTING:
        case IPV6_EXT_FRAGMENT:
        case IPV6_EXT_ESP:
        case IPV6_EXT_AUTH:
        case IPV6_EXT_DEST:
        case IPV6_EXT_MOBILITY:
            if(*size < sizeof(struct ip6_ext))
                return 0;
            struct ip6_ext *ext = (struct ip6_ext *)(*packet);
            if(*size < (long unsigned int)(ext->ip6e_len + 1) * 8)
                return 0;
            *ul = ext->ip6e_nxt;
            *packet = *packet + (ext->ip6e_len + 1) * 8;
            *size = *size - (ext->ip6e_len + 1) * 8;
            return 1;
            break;
        default:
            return 0;
    }
}

const u_char *uncaps_ipv6(const u_char *packet, struct ip6_hdr **head, uint8_t *ul, long unsigned int *size, int verbose){
    struct ip6_hdr *ip6Header = (struct ip6_hdr *) packet;
    char dstAddr[INET6_ADDRSTRLEN];
    char srcAddr[INET6_ADDRSTRLEN];

    //check size
    if(*size < sizeof(struct ip6_hdr))
        return NULL;

    printf("IPv6");
    if(verbose != VERBOSE_LOW){
        printf("\n");
        printf("  Destination: %s  Source: %s\n", inet_ntop(AF_INET6, &ip6Header->ip6_dst, dstAddr, INET6_ADDRSTRLEN), inet_ntop(AF_INET6, &ip6Header->ip6_src, srcAddr, INET6_ADDRSTRLEN));
    }
    if(verbose == VERBOSE_FULL){
        printf("  Version: %d\n", (ntohl(ip6Header->ip6_flow) & VERSION_MASK) >> 28);
        printf("  Class de trafic: %d\n", (ntohl(ip6Header->ip6_flow) & TRAFFIC_CLASS_MASK) >> 20);
        printf("  Label de flow: 0x%x\n", ntohl(ip6Header->ip6_flow) & FLOW_LABEL_MASK);
        printf("  Taille du payload: %d\n", ntohs(ip6Header->ip6_plen));
        printf("  Prochain header: ");
        printHeaderType(ip6Header->ip6_nxt);
        printf("\n");
        printf("  Limite de saut: %d\n", ip6Header->ip6_hlim);
    }
    *ul = ip6Header->ip6_nxt;

    if(head != NULL)
        *head = ip6Header;
    *size = *size - sizeof(struct ip6_hdr);
    packet = packet + sizeof(struct ip6_hdr);

    while(extentionHeader(&packet, ul, size, verbose) == 1);

    return packet;
}

const u_char *uncaps_icmpv6(const u_char *packet, struct icmp6_hdr **head, long unsigned int *size, int verbose){
    struct icmp6_hdr *icmp6Header = (struct icmp6_hdr *) packet;

    //check size
    if(*size < sizeof(struct icmp6_hdr))
        return NULL;


    printf("ICMPv6");
    if(verbose > VERBOSE_LOW){
        printf("\n");
        switch (icmp6Header->icmp6_type){
            case ICMP6_DST_UNREACH:
                printf("  Déstination inatteignable: raison(%d)\n", icmp6Header->icmp6_code);
                break;
            case ICMP6_PACKET_TOO_BIG:
                printf("  Paquet trop gros: MTU = %d\n", ntohs(icmp6Header->icmp6_mtu));
                break;
            case ICMP6_ECHO_REPLY:
                printf("  Echo Reply: identifier = %d, numéros de séquence = %d\n", ntohs(icmp6Header->icmp6_id), ntohs(icmp6Header->icmp6_seq));
                break;
            case ICMP6_ECHO_REQUEST:
                printf("  Echo Request: identifier = %d, numéros de séquence = %d\n", ntohs(icmp6Header->icmp6_id), ntohs(icmp6Header->icmp6_seq));         
                break;
            default:
                printf("  Type: %d  Code: %d\n", icmp6Header->icmp6_type, icmp6Header->icmp6_code);   
        }
    }

    if(head != NULL)
        *head = icmp6Header;
    *size = 0;
    packet = packet + sizeof(struct icmp6_hdr);
    return packet;
}