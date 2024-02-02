#include "ether.h"
#include "verbose.h"
#include <stdio.h>
#include <netinet/in.h>

const u_char *uncaps_ether(const u_char *packet, struct ether_header **head, long unsigned int *size, int verbose){
    struct ether_header * eternetHeader = (struct ether_header *)packet;

    //check size
    if(*size < sizeof(struct ether_header)){
        return NULL;
    }

    printf("Ethernet");
    if(verbose > VERBOSE_LOW){
        printf("\n");
        printf("  Destination: %02x-%02x-%02x-%02x-%02x-%02x   Source: %02x-%02x-%02x-%02x-%02x-%02x \n",
               eternetHeader->ether_dhost[0], eternetHeader->ether_dhost[1],
               eternetHeader->ether_dhost[2], eternetHeader->ether_dhost[3],
               eternetHeader->ether_dhost[4], eternetHeader->ether_dhost[5],
               eternetHeader->ether_shost[0], eternetHeader->ether_shost[1],
               eternetHeader->ether_shost[2], eternetHeader->ether_shost[3],
               eternetHeader->ether_shost[4], eternetHeader->ether_shost[5]);
    }
    if(verbose == VERBOSE_FULL){        
        printf("  ether type: 0x%04x\n", ntohs(eternetHeader->ether_type));
    }

    if(head != NULL)
        *head = eternetHeader;
    *size = *size - sizeof(struct ether_header);
    return packet + sizeof(struct ether_header);
}


const u_char *uncaps_arp(const u_char *packet, struct arphdr **head, long unsigned int *size, int verbose){
    struct arphdr *arpHeader = (struct arphdr *)packet;

    //Check size
    if(*size < (sizeof(struct arphdr) + 2*arpHeader->ar_hln + 2*arpHeader->ar_pln))
        return NULL;

    const u_char *hardware_source_addr = packet + sizeof(struct arphdr);
    const u_char *protocol_source_addr = hardware_source_addr + arpHeader->ar_hln;
    const u_char *hardware_target_addr = protocol_source_addr + arpHeader->ar_pln;
    const u_char *protocol_target_addr = hardware_target_addr + arpHeader->ar_hln;


    printf("ARP");
    if(verbose > VERBOSE_LOW){
        printf("\n");
        if(ntohs(arpHeader->ar_op) == ARPOP_REQUEST) printf(" ARP request\n");
        else if(ntohs(arpHeader->ar_op) == ARPOP_REPLY) printf(" ARP reply\n");
        else if(ntohs(arpHeader->ar_op) == ARPOP_RREQUEST) printf(" RARP request\n");
        else if(ntohs(arpHeader->ar_op) == ARPOP_RREPLY) printf(" RARP reply\n");
        else if(ntohs(arpHeader->ar_op) == ARPOP_InREQUEST) printf(" InARP request\n");
        else if(ntohs(arpHeader->ar_op) == ARPOP_InREPLY) printf(" InARP reply\n");
        else if(ntohs(arpHeader->ar_op == ARPOP_NAK)) printf(" ARP NAK\n");
        else printf(" Opcode: %x\n", ntohs(arpHeader->ar_op));
    }
    if(verbose == VERBOSE_FULL){
        printf("  Format de l'adresse physique: %x\n", ntohs(arpHeader->ar_hrd));
        printf("  Format de l'adresse protocolaire: %x\n", ntohs(arpHeader->ar_pro));
        printf("  Taille de l'adresse physique: %x\n", arpHeader->ar_hln);
        printf("  Taille de l'adresse protocolaire: %x\n", arpHeader->ar_pln);
        printf("  Adresse destination physique:");
        for(unsigned char i=0; i<arpHeader->ar_hln; i++) printf(" %02x", *(hardware_source_addr++));
        printf("\n");
        printf("  Adresse destination protocolaire: ");
        for(unsigned char i=0; i<arpHeader->ar_pln; i++) printf("%d.", *(protocol_source_addr++));
        printf("\b\n");
        printf("  Adresse cible physique:");
        for(unsigned char i=0; i<arpHeader->ar_hln; i++) printf(" %02x", *(hardware_target_addr++));
        printf("\n");
        printf("  Adresse cible protocolaire: ");
        for(unsigned char i=0; i<arpHeader->ar_pln; i++) printf("%d.", *(protocol_target_addr++));
        printf("\b\n");
    }

    if(head != NULL)
        *head = arpHeader;
    *size = *size - sizeof(struct arphdr) + 2*arpHeader->ar_hln + 2*arpHeader->ar_pln;
    return packet + sizeof(struct arphdr) + 2*arpHeader->ar_hln + 2*arpHeader->ar_pln;
}