#include "tools.h"

int codecheck(const u_char *s){
    if( *s < '0' || *s > '9' )
        return 0;
    if( *(s+1) < '0' || *(s+1) > '9' )
        return 0;
    if( *(s+2) < '0' || *(s+2) > '9' )  
        return 0; 
    return 1;
}

long unsigned int min(long unsigned int v1, long unsigned int v2){
    if(v1 < v2)
        return v1;
    return v2;
}