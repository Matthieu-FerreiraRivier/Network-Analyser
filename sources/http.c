#include "http.h"
#include "verbose.h"
#include <string.h>
#include <stdio.h>

void httpRequest(const u_char *packet, long unsigned int size, int verbose){
    int c;
    
    printf("HTTP");

    //check if it's the beginning
    if(size < 4 || (memcmp(packet, "GET", 3) != 0 && memcmp(packet, "HEAD", 4) != 0 && memcmp(packet, "POST", 4) != 0)){
        if(verbose == VERBOSE_FULL){
            printf("\n  Format inconnu, données:[\n");
            fwrite(packet, size, 1, stdout);
            printf("\n]\n");
        }
        return;
    }

    if(verbose == VERBOSE_LOW)
        return;

    //request
    c = 0;
    while(size >=2 && (*(packet+c) != '\r' || *(packet+c+1) != '\n')){
        c++;
        size--;
    }
    printf("\n  ");
    fwrite(packet, c, 1, stdout);
    if(size < 2){
        fwrite(packet+c, size, 1, stdout);
        printf("\n");
        return;
    }
    printf("\n");
    packet = packet + c + 2;
    size = size - 2;

    if(verbose != VERBOSE_FULL)
        return;
    
    //head
    while(size >= 2 && (*packet != '\r' || *(packet+1) != '\n')){
        c = 0;
        while(size >=2 && (*(packet+c) != '\r' || *(packet+c+1) != '\n')){
            c++;
            size--;
        }
        printf("  ");
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
    if(size < 2){
        printf("  ");
        fwrite(packet, size, 1, stdout);
        printf("\n");
        return;
    }
    packet = packet + 2;
    size = size - 2;

    //body
    if(size != 0){
        printf("\n  Body:\n");
        fwrite(packet, size, 1, stdout);
    }
    return;
}


void httpReply(const u_char *packet, long unsigned int size, int verbose){
    int c;
    
    printf("HTTP");

    //status
    if(size < 4 || memcmp(packet, "HTTP", 4) != 0){
        if(verbose == VERBOSE_FULL){
            printf("\n  Format inconnu, données:[\n");
            fwrite(packet, size, 1, stdout);
            printf("\n]\n");
        return;
        }
    }

    if(verbose == VERBOSE_LOW)
        return;

    c = 0;
    while(size >=2 && (*(packet+c) != '\r' || *(packet+c+1) != '\n')){
        c++;
        size--;
    }
    printf("\n  ");
    fwrite(packet, c, 1, stdout);
    if(size < 2){
        fwrite(packet+c, size, 1, stdout);
        printf("\n");
        return;
    }
    printf("\n");
    packet = packet + c + 2;
    size = size - 2;

    if(verbose != VERBOSE_FULL)
        return;

    //head
    while(size >= 2 && (*packet != '\r' || *(packet+1) != '\n')){
        c = 0;
        while(size >=2 && (*(packet+c) != '\r' || *(packet+c+1) != '\n')){
            c++;
            size--;
        }
        printf("  ");
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
    if(size < 2){
        printf("  ");
        fwrite(packet, size, 1, stdout);
        printf("\n");
        return;
    }
    packet = packet + 2;
    size = size - 2;

    //body
    if(size != 0){
        printf("\n  Body:\n");
        fwrite(packet, size, 1, stdout);
    }
    return;
}