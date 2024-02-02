#include "smtp.h"
#include "verbose.h"
#include <stdio.h>
#include <string.h>
#include "tools.h"

int memcmpsmtp(const void *s){
    if(memcmp(s, "HELO", 4) == 0)
        return 1;
    if(memcmp(s, "EHLO", 4) == 0)
        return 1;
    if(memcmp(s, "MAIL", 4) == 0)
        return 1;
    if(memcmp(s, "RCPT", 4) == 0)
        return 1;
    if(memcmp(s, "DATA", 4) == 0)
        return 1;
    if(memcmp(s, "RSET", 4) == 0)
        return 1;
    if(memcmp(s, "VRFY", 4) == 0)
        return 1;
    if(memcmp(s, "EXPN", 4) == 0)
        return 1;
    if(memcmp(s, "HELP", 4) == 0)
        return 1;
    if(memcmp(s, "NOOP", 4) == 0)
        return 1;
    if(memcmp(s, "QUIT", 4) == 0)
        return 1;
    if(memcmp(s, "TURN", 4) == 0)
        return 1;
    if(memcmp(s, "SEND", 4) == 0)
        return 1;
    if(memcmp(s, "SOML", 4) == 0)
        return 1;
    if(memcmp(s, "SAML", 4) == 0)
        return 1;
    return 0;
}

void smtpRequest(const u_char *packet, long unsigned int size, int verbose){
    printf("SMTP");

    //check if it's the beginning
    //it can also be a data message
    if(size < 4 || memcmpsmtp(packet) == 0){
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
    printf("\n  Commade: ");
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


void smtpReply(const u_char *packet, long unsigned int size, int verbose){
    printf("SMTP");

    //check if it's the beginning
    if(size < 3 || codecheck(packet) == 0){
        if(verbose == VERBOSE_FULL){
            printf("\n  Format inconnu, données:[\n");
            fwrite(packet, size, 1, stdout);
            printf("\n]\n");
        }
        return;
    }

    if(verbose == VERBOSE_LOW)
        return;

    //reply code
    printf("\n  ");
    fwrite(packet, 3, 1, stdout);
    packet = packet + 3;
    size = size - 3;

    if(verbose != VERBOSE_FULL){
        printf("\n");
        return;
    }

    //text message
    int c = 0;
    //first ligne
    if(size > 1){
        printf(" ");
        packet = packet + 1;
        size = size - 1;
    }

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
    while(size > 4){
        printf("      ");
        packet = packet + 4;
        size = size - 4;

        c = 0;
        while(size >=2 && (*(packet+c) != '\r' || *(packet+c+1) != '\n')){
            c++;
            size--;
        }
        fwrite(packet, c, 1, stdout);
        printf("\n");
        if(size < 2){
            fwrite(packet+c, size, 1, stdout);
            return;
        }
        printf("\n");
        packet = packet + c + 2;
        size = size - 2;
    }
    
    return;
}