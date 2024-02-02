#include "ip.h"
#include <arpa/inet.h>
#include "verbose.h"
#include <stdio.h>


#define IPOPT_NOP_LEN 1
#define IPOPT_SATID_LEN 4
#define FRAG_DF 0x4000
#define FRAG_MF 0x2000
#define FRAG_OFF 0x1fff

struct ip_security{
    uint8_t code;
    uint8_t len;
    uint16_t S;
    uint16_t C;
    uint16_t H;
    unsigned int TTC:24;
};

struct RR{
    uint8_t code;
    uint8_t len;
    uint8_t pointer;
    uint32_t route[];
} __attribute__((packed));


void showSecurityOption(struct ip_security s){
    printf("  Option Securité(130):");
    switch(ntohs(s.S)){
        case IPOPT_SECUR_UNCLASS:   //Unclassified
            printf(" Unclassified");
            break;
        case IPOPT_SECUR_CONFID:    //Confidential
            printf(" Confidential");
            break;
        case IPOPT_SECUR_EFTO:      //EFTO
            printf(" EFTO");
            break;
        case IPOPT_SECUR_MMMM:      //MMMM
            printf(" MMMM");
            break;
        case IPOPT_SECUR_RESTR:     //Restricted
            printf(" Restricted");
            break;
        case IPOPT_SECUR_SECRET:    //Secret
            printf(" Secret");
            break;
        case IPOPT_SECUR_TOPSECRET: //Top Secret
            printf(" Top Secret");
            break;
        default:
            printf(" Unknown level of security");
    }
    if(ntohs(s.C)) printf(" Compartimenter");
    printf(" H field:%d", ntohs(s.H));
    printf(" TTC filed:%x", ntohl(s.TTC)>>8); //shift de 8 pour compenser le décalage induit par ntohl qui fonctionne sur 32 bits, TTC est ecrit sur 24 bits
    printf("\n");
    return;
}

void showRROption(struct RR *l){
    char networkAddr[INET_ADDRSTRLEN];
    switch(l->code){
        case IPOPT_RR:
            printf("  Option Record Route(7):");
            break;
        case IPOPT_LSRR:
            printf("  Option Loose Source and Record Route(131)");
            break;
        case IPOPT_SSRR:
            printf("  Option Strict Source and Record Route(137):");
            break;
    }
    for(int i=0; i<((l->len-3)/4); i++){
        if(i == (l->pointer/4))
            printf("  **%s**", inet_ntop(AF_INET, &l->route[i], networkAddr, INET_ADDRSTRLEN));
        else
            printf("  %s", inet_ntop(AF_INET, &l->route[i], networkAddr, INET_ADDRSTRLEN));
    }
    printf("\n");
}

const u_char *uncaps_ip(const u_char *packet, struct iphdr **head, long unsigned int *size, int verbose){
    struct iphdr *ipHeader = (struct iphdr *)packet;
    char dstAddr[INET_ADDRSTRLEN];
    char srcAddr[INET_ADDRSTRLEN];

    //Check size
    if(*size < sizeof(struct iphdr))
        return NULL;
    if(*size < (ipHeader->ihl * 4))
        return NULL;

    printf("IP");
    if(verbose != VERBOSE_LOW){
        printf("\n");
        printf("  Destination: %s  Source: %s\n", inet_ntop(AF_INET, &ipHeader->daddr, dstAddr, INET_ADDRSTRLEN), inet_ntop(AF_INET, &ipHeader->saddr, srcAddr, INET_ADDRSTRLEN));
    }
    if(verbose == VERBOSE_FULL){
        printf("  Version: %d\n", ipHeader->version);
        printf("  IHL: %d\n", ipHeader->ihl);
        printf("  TTL: %d\n", ipHeader->ttl);
        printf("  Type Of Service: 0x%x\n", ipHeader->tos);
        printf("  Protocol: Ox%x\n", ipHeader->protocol);
        if(ipHeader->frag_off & FRAG_DF)
            printf("  Pas de Fragmentation\n");
        else{
            printf("  Fragmentation autorisée\n");
            if(ipHeader->frag_off & FRAG_OFF){
                printf("  Offset: %d\n", ipHeader->frag_off & FRAG_OFF);
                if(ipHeader->frag_off & FRAG_MF)
                    printf("  Dernier fragments\n");
                else
                    printf("  Pas le dernier fragments\n");
            }
        }
    }

    //Traitement des options ip.
    if(verbose == VERBOSE_FULL){
        const u_char *option = packet + sizeof(struct iphdr);
        int options_size = (ipHeader->ihl * 4) - sizeof(struct iphdr);
        while(options_size > 0 && *option != IPOPT_END){
            uint8_t lenght;
            switch(*option){
                struct RR *l;
                case IPOPT_NOP:         //No Operation
                    lenght = IPOPT_NOP_LEN;
                    break;
                case IPOPT_SECURITY:    //Security
                    struct ip_security s = *(struct ip_security *)option;
                    lenght = s.len;
                    showSecurityOption(s);
                    break;
                case IPOPT_LSRR:        //Loose Source and Record Route
                    l = (struct RR *)option;
                    lenght = l->len;
                    showRROption(l);
                    break;
                case IPOPT_SSRR:        //Strict Source and Record Route
                    l = (struct RR *)option;
                    lenght = l->len;
                    showRROption(l);
                    break;
                case IPOPT_RR:          //Record Route
                    l = (struct RR *)option;
                    lenght = l->len;
                    showRROption(l);
                    break;
                case IPOPT_SATID:       //Stream Identifier
                    lenght = IPOPT_SATID_LEN;
                    printf("  Option Stream Identifier(136): Ox%x\n", ntohs(*(uint16_t *)(option+2)));
                    break;
                case IPOPT_TS:          //Internet Timestamp
                    
                default:                //Unknown Option
                    lenght = *(option+1);
                    printf("  Option inconue: <");
                    for(int i; i<lenght; i++){
                        if(i % 2 == 0)
                            printf(" ");
                        printf("%02x", *(option + i));
                    }
                    printf(" >\n");
            }
            option = option + lenght;
            options_size = options_size - lenght;
        }
    }

    if(head != NULL)
        *head = ipHeader;
    *size = *size - (ipHeader->ihl * 4);
    return packet + (ipHeader->ihl * 4);
}


const u_char *uncaps_icmp(const u_char *packet, struct icmphdr **head, long unsigned int *size, int verbose){
    struct icmphdr *icmpHeader = (struct icmphdr *)packet;
    
    //Check size
    if(*size < sizeof(struct icmphdr))
        return NULL;

    printf("ICMP");
    if(verbose > VERBOSE_LOW){
        printf("\n");
        switch(icmpHeader->type){
            case ICMP_ECHOREPLY:
                printf("  Echo Reply: identifier = %d, numéros de séquence = %d\n", ntohs(icmpHeader->un.echo.id), ntohs(icmpHeader->un.echo.sequence));
                break;
            case ICMP_ECHO:
                printf("  Echo Request: identifier = %d, numéros de séquence = %d\n", ntohs(icmpHeader->un.echo.id), ntohs(icmpHeader->un.echo.sequence));
                break;
            case ICMP_DEST_UNREACH:
                printf("  Déstination inatteignable: raison(%d)\n", icmpHeader->code);
                break;
            default:
                printf("  Type: %d  Code: %d", icmpHeader->type, icmpHeader->code);
        }
    }

    if(head != NULL)
        *head = icmpHeader;
    packet = packet + *size; //Fin du packet
    *size = 0;
    return packet;
}