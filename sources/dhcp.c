#include "dhcp.h"
#include "bootp.h"
#include "verbose.h"
#include <stdio.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include "tools.h"

#define VEND_MAXSIZE 64


void vendor(u_int8_t *vend, long unsigned int size){
    long unsigned int i = 4;

    while(i < min(VEND_MAXSIZE , size) && vend[i] != TAG_END){
        //check if option is vaild i.e. the given is not off border. 
        if(vend[i] != TAG_PAD && i >= min(VEND_MAXSIZE, size)-1 && i+2+vend[i+1] > min(VEND_MAXSIZE, size))
            return;

        switch(vend[i]){
            case TAG_PAD:
                i++;
                break;
            case TAG_SUBNET_MASK:
                printf("  Masque de sous-réseau: ");
                for(int j=0; j<vend[i+1]; j++){
                    printf("%d", vend[i+2+j]);
                    if(j != vend[i+1]-1)
                        printf(".");
                }
                printf("\n");
                i = i + 2 + vend[i+1];
                break;
            case TAG_GATEWAY:
                printf("  Passerelle: ");
                for(int j=0; j<vend[i+1]; j++){
                    printf("%d", vend[i+2+j]);
                    if(j != vend[i+1]-1)
                        printf(".");
                }
                printf("\n");
                i = i + 2 + vend[i+1];
                break;
            case TAG_TIME_SERVER:
                printf("  Serveur de temps: ");
                for(int j=0; j<vend[i+1]; j++){
                    printf("%d", vend[i+2+j]);
                    if(j != vend[i+1]-1)
                        printf(".");
                }
                printf("\n");
                i = i + 2 + vend[i+1];
                break;
            case TAG_NAME_SERVER:
                printf("  Serveur de nom: ");
                for(int j=0; j<vend[i+1]; j++){
                    printf("%d", vend[i+2+j]);
                    if(j != vend[i+1]-1)
                        printf(".");
                }
                printf("\n");
                i = i + 2 + vend[i+1];
                break;
            case TAG_DOMAIN_SERVER:
                printf("  Serveur de domaine: ");
                for(int j=0; j<vend[i+1]; j++){
                    printf("%d", vend[i+2+j]);
                    if(j != vend[i+1]-1)
                        printf(".");
                }
                printf("\n");
                i = i + 2 + vend[i+1];
                break;
            case TAG_DHCP_MESSAGE:
                printf(" DHCP: ");
                switch(vend[i+2]){
                    case DHCPDISCOVER:
                        printf("DHCP Discover\n");
                        break;
                    case DHCPOFFER:
                        printf("DHCP Offer\n");
                        break;
                    case DHCPREQUEST:
                        printf("DHCP Request\n");
                        break;
                    case DHCPDECLINE:
                        printf("DHCP Decline\n");
                        break;
                    case DHCPACK:
                        printf("DHCP Ack\n");
                        break;
                    case DHCPNAK:
                        printf("DHCP Nak\n");
                        break;
                    case DHCPRELEASE:
                        printf("DHCP Release\n");
                        break;
                    case DHCPINFORM:
                        printf("DHCP Inform\n");
                        break;
                    default:
                        printf("  DHCP inconnu: %d\n", vend[i+2]);
                }
                i = i + 2 + vend[i+1];
                break;
            case TAG_HOSTNAME:
                printf("  Nom d'hôte: ");
                for(int j=0; j<vend[i+1] && vend[i+2+j]; j++){
                    printf("%c", vend[i+2+j]);
                }
                printf("\n");
                i = i + 2 + vend[i+1];
                break;
            case TAG_PARM_REQUEST:
                printf("  Paramètres demandés: ");
                for(int j=0; j<vend[i+1]; j++){
                    printf("%d", vend[i+2+j]);
                    if(j != vend[i+1]-1)
                        printf(", ");
                }
                printf("\n");
                i = i + 2 + vend[i+1];
                break;
            case TAG_DOMAINNAME:
                printf("  Nom de domaine: ");
                for(int j=0; j<vend[i+1] && vend[i+2+j]; j++){
                    printf("%c", vend[i+2+j]);
                }
                printf("\n");
                i = i + 2 + vend[i+1];
                break;
            default:
                printf("  Tag inconnu: %d  valeurs: <", vend[i]);
                for(int j=0; j<vend[i+1]; j++){
                    printf("%02x", vend[i+2+j]);
                    if(j != vend[i+1]-1)
                        printf(" ");
                }
                printf(">\n");
                i = i + 2 + vend[i+1];
        }
    }
    return;
}


void dhcpMessage(const u_char *packet, long unsigned int size, int verbose){
    struct bootp *data = (struct bootp *)packet;
    u_int8_t magicCookie[4] = VM_RFC1048;

    //check size
    if(size < sizeof(struct bootp)){
        printf("Mauvais format BOOTP, analyse imposible.\n");
        return;
    }

    if(verbose == VERBOSE_LOW){
        printf("BOOTP");
        return;
    }

    printf("BOOTP\n");
    switch(data->bp_op){
        case BOOTPREPLY:
            printf("  Réponse BOOTP\n");
            break;
        case BOOTPREQUEST:
            printf("  Requête BOOTP\n");
            break;
        default:
            printf("  Opcode incorrect (%d)\n", data->bp_op);
        }

    if(verbose != VERBOSE_FULL)
        return;

    if(data->bp_htype == 1)
        printf("  Type hardware: ethernet\n");
    else
        printf("  Type hardware: %d\n", data->bp_htype);
    printf("  Taille adresse hardware: %d\n", data->bp_hlen);
    printf("  Nombre de saut: %d\n", data->bp_hops);
    printf("  Identifiant de transaction: %08x\n", data->bp_xid);
    if(data->bp_secs) printf("  durée du boot: %d", ntohs(data->bp_secs));

    printf("  Adresse IP client: %s\n", inet_ntoa(data->bp_ciaddr));
    printf("  Adresse IP serveur: %s\n", inet_ntoa(data->bp_siaddr));
    printf("  Adresse IP passerelle: %s\n", inet_ntoa(data->bp_giaddr));
    printf("  Adresse IP attribué par le serveur: %s\n", inet_ntoa(data->bp_yiaddr));

    printf("  Adresse MAC client: ");
    for(int i=0; i<data->bp_hlen; i++){
        printf("%02x", data->bp_chaddr[i]);
        if(i != data->bp_hlen-1)
            printf("-");
    }
    printf("\n");

    printf("  Nom du serveur: ");
    for(int i=0; i<64; i++){
        if(data->bp_sname[i] == '\0')
            break;
        printf("%c", data->bp_sname[i]);
    }
    printf("\n");
    printf("  Nom du fichier: ");
    for(int i=0; i<128; i++){
        if(data->bp_file[i] == '\0')
            break;
        printf("%c", data->bp_file[i]);
    }
    printf("\n");

    if(memcmp(magicCookie, data->bp_vend, 4) != 0)
        return;
    vendor(data->bp_vend, size-sizeof(struct bootp));

    return;
}