#include "transport.h"
#include "verbose.h"
#include <stdio.h>
#include <netinet/in.h>

#define TCPOLEN_NOP 1

const u_char *uncaps_udp(const u_char *packet, struct udphdr **head, long unsigned int *size, int verbose){
    struct udphdr *udpHeader = (struct udphdr *)packet;

    //Check size
    if(*size < sizeof(struct udphdr))
        return NULL;

    printf("UDP");
    if(verbose > VERBOSE_LOW){
        printf("\n");
        printf("  Port déstination: %d  Port source: %d\n", ntohs(udpHeader->dest), ntohs(udpHeader->source));
    }
    if(verbose == VERBOSE_FULL)
        printf("  Taille du paquet: %d\n", ntohs(udpHeader->len));

    if(head != NULL)
        *head = udpHeader;
    *size = *size - sizeof(struct udphdr);
    return packet + sizeof(struct udphdr);
}


const u_char *uncaps_tcp(const u_char *packet, struct tcphdr **head, long unsigned int *size, int verbose){
    struct tcphdr *tcpHeader = (struct tcphdr *)packet;

    //Check size
    if(*size < sizeof(struct tcphdr))
        return NULL;
    if(*size < (tcpHeader->doff *4))
        return NULL;

    printf("TCP");
    if(verbose > VERBOSE_LOW){
        printf("\n");
        printf("  Port destination: %d  Port source: %d\n", ntohs(tcpHeader->dest), ntohs(tcpHeader->source));
        if(tcpHeader->urg) printf("  URGENT");
        if(tcpHeader->ack) printf("  ACK");
        if(tcpHeader->psh) printf("  PUSH");
        if(tcpHeader->rst) printf("  RESET");
        if(tcpHeader->syn) printf("  SYN");
        if(tcpHeader->fin) printf("  FIN");
        printf("\n");
    }
    if(verbose == VERBOSE_FULL){
        printf("  Numéro de séquence: %u  Numéro d'aquitement: %u\n", ntohl(tcpHeader->seq), ntohl(tcpHeader->ack_seq));
        printf("  Taille de la fenêtre: %u\n", ntohs(tcpHeader->window));
    }

    //traitement des oprions TCP
    if(verbose == VERBOSE_FULL){
        const u_char *option = packet + sizeof(struct tcphdr);
        int options_size = (tcpHeader->doff * 4) - sizeof(struct tcphdr);
        while(options_size > 0 && *option != TCPOPT_EOL){
            uint8_t lenght;
            switch(*option){
                case TCPOPT_NOP:         //No Operation
                    lenght = TCPOLEN_NOP;
                    break;
                case TCPOPT_MAXSEG:     //Maximum Segment Size
                    lenght = TCPOLEN_MAXSEG;
                    printf("  Option Maximum Segment Size(2): %d\n", ntohs(*(uint16_t *)(option+2)));
                    break;
                case TCPOPT_WINDOW:     // Window Scale
                    lenght = TCPOLEN_WINDOW;
                    printf("  Option Window Scale(3): Scale factor is 2^%d.\n", *(option+2));
                    break;
                case TCPOPT_SACK_PERMITTED: // Selective Ack permitted
                    lenght = TCPOLEN_SACK_PERMITTED;
                    printf("  Option Selective Ack Permitted(4): Permitted\n");
                    break;
                case TCPOPT_SACK:       //Selective Ack
                    lenght = *(option+1);
                    int nbBlock = (lenght-2)/2;
                    printf("  Selective Ack:\n");
                    for(int i=0; i<nbBlock; i++){
                        printf("   %d to %d are acquitted\n", ntohl(*(uint32_t *)(option+2+2*i)), ntohl(*(uint32_t *)(option+2+2*i+1)));
                    }
                    break;
                default:                //Unknown Option
                    lenght = *(option+1);
                    printf("  Unknow Option: <");
                    for(int i=0; i<lenght; i++){
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
        *head = tcpHeader;
    *size = *size - (tcpHeader->doff * 4);
    return packet + (tcpHeader->doff * 4);
}