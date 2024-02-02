#include "dns.h"
#include "verbose.h"
#include <string.h>
#include <stdio.h>
#include <netinet/in.h>

#define P_MASK 0b11000000
#define OFF_MASK 0b00111111

struct dnshdr{
    uint16_t id;
    uint8_t qr:1;
    uint8_t opcode:4;
    uint8_t aa:1;
    uint8_t tc:1;
    uint8_t rd:1;
    uint8_t ra:1;
    uint8_t z:3;
    uint8_t rcode:4;
    uint16_t qdcount;
    uint16_t ancount;
    uint16_t nscount;
    uint16_t arcount;
} __attribute__((packed));

/*
  Varriable use by 'printName' to indicate the beginning of the message.
 It must be initialise with 'printName_init'
*/
const u_char *begin;

/*
  Inisialise 'begin' at the beginning of the message.
*/
void printName_init(const u_char *message){
  begin = message;
  return;
}

/*
  Print a Name. It return a pointer just after the name and update
  the size. Must be call after printName_init for a specific message.
*/
const u_char *printName(const u_char *name, long unsigned int *size){
    if(*size != 0 && *name == 0){
        printf("ROOT");
        (*size)--;
        return ++name;
    }

    while(*size != 0 && *name != 0){
        //check if the current label is a pointer
        if(((*name) & P_MASK) == P_MASK ){
            if(*size < 2)
                return NULL;
            
            uint16_t off = ntohs(*((uint16_t *)name)) & OFF_MASK;
            if((name - begin) + *size < off) //offset out of bound
                return NULL;
            long unsigned int callSize = ((name - begin) + *size) - off;
            if(printName(begin + off, &callSize) == NULL)
                return NULL;

            *size = *size - 2;
            name = name + 2;
            return name;
        }

        u_char len = *(name++);
        (*size)--;
        //check if the current label is not truncated
        if(*size < len)
            return NULL;
        for(int i=0; i<len; i++){
            printf("%c", *(name++));
            (*size)--;
        }
        printf(".");
    }
    printf("\b ");
    (*size)--;
    return ++name;
}

/*
  Print type name corresponding to value
*/
void printType(uint16_t type){
    switch(type){
        case 1:
            printf("A");
            break;
        case 2:
            printf("NS");
            break;
        case 3:
            printf("MD");
            break;
        case 4:
            printf("MF");
            break;
        case 5:
            printf("CNAME");
            break;
        case 6:
            printf("SOA");
            break;
        case 7:
            printf("MB");
            break;
        case 8:
            printf("MG");
            break;
        case 9:
            printf("MR");
            break;
        case 10:
            printf("NULL");
            break;
        case 11:
            printf("WKS");
            break;
        case 12:
            printf("PTR");
            break;
        case 13:
            printf("HINFO");
            break;
        case 14:
            printf("MINFO");
            break;
        case 15:
            printf("MX");
            break;
        case 16:
            printf("TXT");
            break;
        case 28:
            printf("AAAA");
            break;
        case 41:
            printf("OPT");
            break;
        case 252:
            printf("AXFR");
            break;
        case 253:
            printf("MAILB");
            break;
        case 254:
            printf("MAILA");
            break;
        case 255:
            printf("*");
            break;
        default:
            printf("TYPE %d", type);
    }
    return;
}

/*
  Print class name corresponding to value
*/
void printClass(uint16_t class){
    switch(class){
        case 1:
            printf("IN");
            break;
        case 2:
            printf("CS");
            break;
        case 3:
            printf("CH");
            break;
        case 4:
            printf("HS");
            break;
        case 255:
            printf("*");
            break;
        default:
            printf("CLASS %d", class);
    }
    return;
}

/*
  Show all field from a DNS header.
*/
void showDnsHeader(struct dnshdr *head, int verbose){
    printf("  Entête:\n");

    if(head->qr)
        printf("   Réponse\n");
    else
        printf("   Question\n");
    switch(head->opcode){
        case 0:
            printf("   Standard\n");
            break;
        case 1:
            printf("   Inverse\n");
            break;
        case 2:
            printf("   Serveur d'état\n");
            break;
        default:
            printf("   Opcode %d\n", head->opcode);
    }

    if(verbose != VERBOSE_FULL)
        return;

    printf("   ID: %d\n", ntohs(head->id));
    if(head->aa)
        printf("   Réponse d'autorité\n");
    if(head->tc)
        printf("   Tronqué\n");
    if(head->rd)
        printf("   Recursion souhaité\n");
    if(head->ra)
        printf("   Recursive disponible\n");
    if(head->qr){
        switch(head->rcode){
            case 0:
                printf("   Pas d'erreur\n");
                break;
            case 1:
                printf("   Erreur de Format\n");
                break;
            case 2:
                printf("   Défaillance serveur\n");
                break;
            case 3:
                printf("   Erreur de nom\n");
                break;
            case 4:
                printf("   Pas implémenté\n");
                break;
            case 5:
                printf("   Refusé\n");
                break;
            default:
                printf("   Rcode %d\n", head->rcode);
        }
    }
    printf("   Nombre de questions: %d\n", ntohs(head->qdcount));
    printf("   Nombre de réponses: %d\n", ntohs(head->ancount));
    printf("   Nombre d'autorité: %d\n", ntohs(head->nscount));
    printf("   Nombre d'informations additionel: %d\n", ntohs(head->arcount));

    return;
}

/*
  Show all fied from a DNS question at the pointer 'packet' and return a
  pointer just after it. 
*/
const u_char *getDnsQuestion(const u_char *question, long unsigned int *size){
    printf(" Nom: ");
    if((question = printName(question, size)) == NULL)
        return NULL;
    printf("\n");

    if(*size < 4)
        return NULL;
    uint16_t type = ntohs(*((uint16_t *)question));
    question = question + 2;
    uint16_t class = ntohs(*((uint16_t *)question));
    question = question + 2;
    *size = *size - 4;

    printf("      Type: ");
    printType(type);
    printf("\n");
    printf("      Class: ");
    printClass(class);
    printf("\n");

    return question;
}

/*
  Show all fied from a DNS RR at the pointer 'packet' and return a
  pointer just after it. 
*/
const u_char *getDnsRR(const u_char *rr, long unsigned int *size){
    printf(" Nom: ");
    if((rr = printName(rr, size)) == NULL)
        return NULL;
    printf("\n");

    if(*size < 10)
        return NULL;
    uint16_t type = ntohs(*((uint16_t *)rr));
    rr = rr + 2;
    uint16_t class = ntohs(*((uint16_t *)rr));
    rr = rr + 2;
    uint32_t ttl = ntohl(*((uint32_t *)rr));
    rr = rr + 4;
    uint16_t rdlength = ntohs(*((uint16_t *)rr));
    rr = rr + 2;
    *size = *size - 10;

    printf("      Type: ");
    printType(type);
    printf("\n");
    //print specific field for OPT Pseudo-RR
    if(type == 41){
        printf("      Taille trame UDP: %d\n", class);
        printf("      RCODE et flags: 0x%08x\n", ttl);
        printf("      Longueur des options: %d\n", rdlength);
        if(*size < rdlength)
            return NULL;
        if(rdlength){
            printf("      Options: ");
            for(int i=0; i<rdlength; i++)
                printf("%02x ", rr[i]);
            printf("\n");
        }
        rr = rr + rdlength;
        *size = *size - rdlength;
        return rr;
    }
    printf("      Class: ");
    printClass(class);
    printf("\n");
    printf("      TTL: %d\n", ttl);
    printf("      Longueur: %d\n", rdlength);

    if(*size < rdlength)
        return NULL;
    switch(type){
        case 1:
            if(rdlength != 4)
                return NULL;
            printf("      Adresse: %d.%d.%d.%d\n", rr[0], rr[1], rr[2], rr[3]);
            break;
        case 5:
            printf("      Nom canonique: ");
            if((rr = printName(rr, size)) == NULL)
                return NULL;
            printf("\n");
            return rr;
        case 28:
            if(rdlength != 16)
                return NULL;
            printf("      Adresse: ");
            for(int i=0; i<rdlength; i++){
                printf("%02x", rr[i]);
                if(i%2)
                    printf(":");
            }
            printf("\b \n");
            break;
        default:
            printf("      Données: ");
            for(int i=0; i<rdlength; i++)
                printf("%02x ", rr[i]);
            printf("\n");
    }
    rr = rr + rdlength;
    *size = *size - rdlength;

    return rr;
}


void dnsMessage(const u_char *message, long unsigned int size, int verbose){
    struct dnshdr *head;
    const u_char *question;
    const u_char *rr;

    //check size
        if(size < sizeof(struct dnshdr)){
        printf("Mauvais format DNS, analyse imposible.\n");
        return;
    }

    printf("DNS");
    if(verbose == VERBOSE_LOW)
        return;
    printf("\n");
    printName_init(message);

    head = (struct dnshdr *)message;
    showDnsHeader(head, verbose);
    size = size - sizeof(struct dnshdr);
    question = (const u_char *)(head + 1);

    if(verbose != VERBOSE_FULL)
        return;

    //cross all questions
    if(head->qdcount)
        printf("  Questions:\n");
    for(int i=0; i<ntohs(head->qdcount); i++){
        printf("   %d:", i);
        if((question = getDnsQuestion(question, &size)) == NULL)
            return;
    }
    rr = question;

    //cross all rr
    if(head->ancount)
        printf("  Réponse:\n");
    for(int i=0; i<ntohs(head->ancount); i++){
        printf("   %d:", i);
        if((rr = getDnsRR(rr, &size)) == NULL)
            return;
    }
    if(head->nscount)
        printf("  Autorité:\n");
    for(int i=0; i<ntohs(head->nscount); i++){
        printf("   %d:", i);
        if((rr = getDnsRR(rr, &size)) == NULL)
            return;
    }
    if(head->arcount)
        printf("  Informations additionel:\n");
    for(int i=0; i<ntohs(head->arcount); i++){
        printf("   %d:", i);
        if((rr = getDnsRR(rr, &size)) == NULL)
            return;
    }
    
    return;
}