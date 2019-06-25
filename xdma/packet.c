#include "packet.h"



int createHeader(struct Header *header, int src, int sink, int algo, int mode, int pktid, int length){
    int i;
    header->sync   = SYNC;
    header->src    = src;
    header->sink   = sink;
    header->length = length;
    header->algo   = algo;
    header->mode   = mode;
    header->pktid  = pktid;
    for(i=0; i< 56; i++){
        header->reserved[i] = 0;
    }
    return 1;
}