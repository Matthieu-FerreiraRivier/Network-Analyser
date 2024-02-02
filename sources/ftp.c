#include "ftp.h"
#include "verbose.h"
#include <stdio.h>
#include <string.h>
#include "tools.h"

int memcmpftp(const void *s){
    if(memcmp(s, "USER", 4) == 0)
        return 1;
    if(memcmp(s, "PASS", 4) == 0)
        return 1;
    if(memcmp(s, "ACCT", 4) == 0)
        return 1;
    if(memcmp(s, "CWD", 3) == 0)
        return 1;
    if(memcmp(s, "CDUP", 4) == 0)
        return 1;
    if(memcmp(s, "SMNT", 4) == 0)
        return 1;
    if(memcmp(s, "REIN", 4) == 0)
        return 1;
    if(memcmp(s, "QUIT", 4) == 0)
        return 1;
    if(memcmp(s, "PORT", 4) == 0)
        return 1;
    if(memcmp(s, "PASV", 4) == 0)
        return 1;
    if(memcmp(s, "TYPE", 4) == 0)
        return 1;
    if(memcmp(s, "STRU", 4) == 0)
        return 1;
    if(memcmp(s, "MODE", 4) == 0)
        return 1;
    if(memcmp(s, "RETR", 4) == 0)
        return 1;
    if(memcmp(s, "STOR", 4) == 0)
        return 1;
    if(memcmp(s, "STOU", 4) == 0)
        return 1;
    if(memcmp(s, "APPE", 4) == 0)
        return 1;
    if(memcmp(s, "ALLO", 4) == 0)
        return 1;
    if(memcmp(s, "REST", 4) == 0)
        return 1;
    if(memcmp(s, "RNFR", 4) == 0)
        return 1;
    if(memcmp(s, "RNTO", 4) == 0)
        return 1;
    if(memcmp(s, "ABOR", 4) == 0)
        return 1;
    if(memcmp(s, "DELE", 4) == 0)
        return 1;
    if(memcmp(s, "RMD", 3) == 0)
        return 1;
    if(memcmp(s, "MKD", 3) == 0)
        return 1;
    if(memcmp(s, "PWD", 3) == 0)
        return 1;
    if(memcmp(s, "LIST", 4) == 0)
        return 1;
    if(memcmp(s, "NLST", 4) == 0)
        return 1;
    if(memcmp(s, "SITE", 4) == 0)
        return 1;
    if(memcmp(s, "SYST", 4) == 0)
        return 1;
    if(memcmp(s, "STAT", 4) == 0)
        return 1;
    if(memcmp(s, "HELP", 4) == 0)
        return 1;
    if(memcmp(s, "NOOP", 4) == 0)
        return 1;
    return 0;

}

void ftpRequest(const u_char *packet, long unsigned int size, int verbose){
    int c = 0;

    printf("FTP");

    //check if it's the beginning
    if(size < 5 || memcmpftp(packet) == 0){
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
    while(size >=2 && (*(packet+c) != '\r' || *(packet+c+1) != '\n')){
        c++;
        size--;
    }
    fwrite(packet, c, 1, stdout);
    if(size < 2){
        fwrite(packet+c, size, 1, stdout);
    }
    printf("\n");

    return;
}


void ftpReply(const u_char *packet, long unsigned int size, int verbose){
    int c;

    printf("FTP");

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
    printf("\n  réponse: ");
    fwrite(packet, 3, 1, stdout);
    packet = packet + 3;
    size = size - 3;

    if(verbose != VERBOSE_FULL)
        return;

    //explicative text
    c = 0;
    printf("(");
    while(size >=2 && (*(packet+c) != '\r' || *(packet+c+1) != '\n')){
        c++;
        size--;
    }
    fwrite(packet, c, 1, stdout);
    if(size < 2){
        fwrite(packet+c, size, 1, stdout);
        printf(" )\n");
        return;
    }
    printf(" )\n");
    packet = packet + c + 2;
    size = size - 2;


    //Content
    if(size != 0){
        printf("  Contenu:\n");
        while(size != 0){
            c = 0;

            printf("   ");

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
    }

    return;
}

/*
  The transfer is assumed to be in STREAM mode and the data is an file-structure 
  (as if all the transfer parameters were the default).   
*/
void ftpData(const u_char *packet, long unsigned int size, int verbose){
    printf("FTP (donées)");

    if(verbose > VERBOSE_LOW){
        printf("\n  taille des données(octet): %lu\n", size);
    }

    if(verbose == VERBOSE_FULL){
        printf("  Contenu:[\n");
        fwrite(packet, size, 1, stdout);
        printf("\n  ]\n");
    }

    return;
}