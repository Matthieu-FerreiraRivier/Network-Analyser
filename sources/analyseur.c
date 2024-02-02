#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <pcap.h>
#include "handler.h"
#include "verbose.h"

#define SNAPLEN 1500
#define PROMISC 0
#define TIMER 0

char errbuf[PCAP_ERRBUF_SIZE];


int main(int argc, char **argv){
    pcap_t *capture = NULL;
    int option;
    struct handler_args args;
    bpf_u_int32 netaddr = 0;
    bpf_u_int32 netmask = 0;
    args.verbose = VERBOSE_LOW;     //By default, the verbosity level is minimal.
    char *filter;
    int filtered = 0;               //No filter is applied by default.

    while((option = getopt(argc, argv, "i:o:f:v:")) != -1){
        switch(option){
        case 'i':
            if(capture != NULL)
                break;
            if(pcap_lookupnet(optarg, &netaddr, &netmask, errbuf) != 0){
                    fprintf(stderr, "Erreur, recherche de l'adesse IP et du masque de sous réseau\n");
            }
            if((capture = pcap_open_live(optarg, SNAPLEN, PROMISC, TIMER, errbuf)) == NULL){
                fprintf(stderr, "Erreur, echec de l'overture de l'interface '%s'.\n", optarg);
                exit(1);
            }
            break;
        case 'o':
            if(capture != NULL) break;
            if((capture = pcap_open_offline(optarg, errbuf)) == NULL){
                fprintf(stderr, "Erreur, echec de l'ouverture du fichier '%s'.\n", optarg);
                exit(1);
            }
            break;
        case 'v':
            switch(atoi(optarg)){
                case 1:
                    args.verbose = VERBOSE_LOW;
                    break;
                case 2:
                    args.verbose = VERBOSE_SYNTH;
                    break;
                case 3:
                    args.verbose = VERBOSE_FULL;
                    break;
                default:
                    pcap_close(capture);
                    fprintf(stderr, "Erreur, niveau de verbosité incorrect.\nusage: analyseur -v <1..3> ...\n");
                    exit(1);
            }
            break;
        case 'f':
            filtered = 1;
            filter = optarg;
            break;
        case '?':
            fprintf(stderr, "Erreur, options incorrects\n");
            exit(1);
        }
    }
    if(capture == NULL){
        fprintf(stderr, "Erreur, aucune capture n'est ouverte.\nusage: analyseur -i <interface> ...\n       analyseur -o <fichier> ...\n");
        exit(1);
    }

    if(filtered && netaddr){
        struct bpf_program fp;

        if(pcap_compile(capture, &fp, filter, 0, netmask) == PCAP_ERROR){
            fprintf(stderr, "Erreur, compilation du filtre\n");
            pcap_close(capture);
            exit(1);
        }
        if(pcap_setfilter(capture, &fp) != 0){
            fprintf(stderr, "Erreur, error on filter");
            pcap_close(capture);
            exit(1);
        }


    }


    if(pcap_loop(capture, -1, handler, (u_char *)&args) != 0){
        fprintf(stderr, "Erreur à la récéption d'un paquet");
        pcap_close(capture);
        exit(1);
    }


    pcap_close(capture);
    return 0;
}