#include "pop.h"
#include "verbose.h"
#include <stdio.h>
#include <string.h>

int memcmppop(const void *s){
    if(memcmp(s, "USER", 4) != 0)
        return 0;
    if(memcmp(s, "PASS", 4) != 0)
        return 0;
    if(memcmp(s, "STAT", 4) != 0)
        return 0;
    if(memcmp(s, "LIST", 4) != 0)
        return 0;
    if(memcmp(s, "RETR", 4) != 0)
        return 0;
    if(memcmp(s, "DELE", 4) != 0)
        return 0;
    if(memcmp(s, "NOOP", 4) != 0)
        return 0;
    if(memcmp(s, "RSET", 4) != 0)
        return 0;
    if(memcmp(s, "QUIT", 4) != 0)
        return 0;
    if(memcmp(s, "APOP", 4) != 0)
        return 0;
    if(memcmp(s, "TOP", 3) != 0)
        return 0;
    if(memcmp(s, "UIDL", 4) != 0)
        return 0;
    return 1;
}


void popRequest(const u_char *packet, long unsigned int size, int verbose){
    printf("POP");

    //check if it's the beginning
    //it can also be a data message
    if(size < 4 || memcmppop(packet) != 0){
        if(verbose == VERBOSE_FULL){
            printf("\n  Format inconnu, données:[\n");
            fwrite(packet, size, 1, stdout);
            printf("\n]\n");
        }
        return;
    }
    
    if(verbose == VERBOSE_LOW)
        return;

    //command
    printf("\n  Commande: ");
    fwrite(packet, 4, 1, stdout);
    packet = packet + 4;
    size = size - 4;

    if(verbose != VERBOSE_FULL){
        printf("\n");
        return;
    }

    //text message
    int c = 0;

    //first ligne
    while(size >=2 && (*(packet+c) != '\r' || *(packet+c+1) != '\n')){
        c++;
        size--;
    }
    fwrite(packet, c, 1, stdout);
    if(size < 2){
        fwrite(packet+c, size, 1, stdout);
        printf("\n");
        return;
    }
    printf("\n");
    packet = packet + c + 2;
    size = size - 2;
    //other ones
    while(size != 0){
        printf("       ");

        c = 0;
        while(size >=2 && (*(packet+c) != '\r' || *(packet+c+1) != '\n')){
            c++;
            size--;
        }
        fwrite(packet, c, 1, stdout);
        if(size < 2){
            fwrite(packet+c, size, 1, stdout);
            printf("\n");
            return;
        }
        printf("\n");
        packet = packet + c + 2;
        size = size - 2;
    }

    return;
}

void popReply(const u_char *packet, long unsigned int size, int verbose){
    printf("POP");

    //check if it's the beginning
    if(size < 3 || (memcmp(packet, "+OK", 3) != 0 && memcmp(packet, "-ER", 3) != 0)){
        if(verbose == VERBOSE_FULL){
            printf("\n  Format inconnu, données:[\n");
            fwrite(packet, size, 1, stdout);
            printf("\n]\n");
        }
        return;
    }

    //Error message
    if(memcmp(packet, "-ER", 3) == 0){
        packet = packet + 3;
        size = size - 3;
        if(verbose == VERBOSE_LOW)
            return;
        printf("\n  POP erreur(-ER)");

        if(verbose != VERBOSE_FULL){
            printf("\n");
            return;
        }
        printf(" raison:");
        fwrite(packet, size, 1, stdout);

        return;
    }

    packet = packet + 3;
    size = size - 3;
    if(verbose == VERBOSE_LOW)
        return;
    printf("\n  POP réponse(+OK)");

    if(verbose != VERBOSE_FULL){
        printf("\n");
        return;
    }
    int c = 0;
    while(size >=2 && (*(packet+c) != '\r' || *(packet+c+1) != '\n')){
        c++;
        size--;
    }
    fwrite(packet, c, 1, stdout);
    if(size < 2){
        fwrite(packet+c, size, 1, stdout);
        printf("\n");
        return;
    }
    printf("\n");
    packet = packet + c + 2;
    size = size - 2;

    if(size != 0){
        printf("\n  Contenu:\n");
        fwrite(packet, size, 1, stdout);
    }
    return;
}