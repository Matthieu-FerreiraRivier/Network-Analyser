#include "imap.h"
#include "verbose.h"
#include <stdio.h>

/*
  For IMAP messages, we don't rebuild the TCP stream. We don't have 
  enough context to perform a more accurate parsing.
*/

void imapMessage(const u_char *packet, long unsigned int size, int verbose){
    printf("IMAP");

    if(verbose != VERBOSE_FULL)
        return;
    printf("\n");

    while(size != 0){
        int c = 0;

        printf("  ");

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