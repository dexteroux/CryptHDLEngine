#include <stdio.h>
#include <string.h>
#include <openssl/engine.h>
#include <openssl/evp.h>
#include "xdma/cxdma.h"
#include "xdma/packet.h"
static EVP_MD digest_sha256;

static char *channelc2h = "/dev/xdma0_c2h_0";
static char *channelh2c = "/dev/xdma0_h2c_0";
static char whitener[256] = {
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};

static int fdc2h, fdh2c;
static unsigned char * padblock;
static int padblockOffset;
static int totalCount;
static int initialised = 0;

#define debug 0
unsigned int LitToBigEndian(unsigned int x)
{
	return (((x>>24) & 0x000000ff) | ((x>>8) & 0x0000ff00) | ((x<<8) & 0x00ff0000) | ((x<<24) & 0xff000000));
}



int printBuff(unsigned char *str, int len){
    int i;
    for(i=0; i < len; i++){
        if (i%64 == 0) printf("\n");
        printf("%02x", str[i]);
    }
    printf("\n");
    return 0;
}

int calculatePadding(unsigned char * padblock, int totalCount){
    int i, mdi, padlen, offset, l1, l2, bcount;
    long length;
    unsigned char* lengthStr;
    
    mdi = totalCount & 0x3F;
    if (mdi < 56){
        padlen = 55-mdi;
        bcount = 1;
    } 
    else{
        padlen = 119-mdi;
        bcount = 2;
    } 
    
    offset = totalCount%64;
    padblock[offset] = 0x80;
    
    length = totalCount<<3;
    l1 = LitToBigEndian(length & 0xFFFFFFFF);
    l2 = LitToBigEndian((length >> 32) & 0xFFFFFFFF);
    length = (long)l1 << 32 | l2;
    lengthStr = (unsigned char*)&length;
    
    for(i=0; i < padlen; i++)
    {
        offset ++;
        padblock[offset] = 0x00;
    }
    for(i=0; i < 8; i++)
    {
        offset ++;
        padblock[offset] = lengthStr[i];
    }
    return bcount;    
}

uint16_t _bswap16(uint16_t a)
{
  a = ((a & 0x00FF) << 8) | ((a & 0xFF00) >> 8);
  return a;
}

uint32_t _bswap32(uint32_t a)
{
  a = ((a & 0x000000FF) << 24) |
      ((a & 0x0000FF00) <<  8) |
      ((a & 0x00FF0000) >>  8) |
      ((a & 0xFF000000) >> 24);
  return a;
}

uint64_t _bswap64(uint64_t a)
{
  a = ((a & 0x00000000000000FFULL) << 56) | 
      ((a & 0x000000000000FF00ULL) << 40) | 
      ((a & 0x0000000000FF0000ULL) << 24) | 
      ((a & 0x00000000FF000000ULL) <<  8) | 
      ((a & 0x000000FF00000000ULL) >>  8) | 
      ((a & 0x0000FF0000000000ULL) >> 24) | 
      ((a & 0x00FF000000000000ULL) >> 40) | 
      ((a & 0xFF00000000000000ULL) >> 56);
  return a;
}

int changeEndian(unsigned char * buff, int len){
    uint32_t *a = (uint32_t *)buff;
    int i;
    for(i=0; i < len/sizeof(uint32_t); i++){
        a[i] = _bswap32(a[i]);
    }
    return 0;    
}

int sendPacket(unsigned char * buff, int totalCount, int mode){
    unsigned char *packet = (unsigned char*) malloc(sizeof(unsigned char)*(totalCount + 64 + 256 + 64));
    struct Header *header = (struct Header*) packet;    
    
    createHeader(header, 0, 1, SHA256, mode, 0, totalCount/64);
    changeEndian((unsigned char *)header, 64);
    memcpy(packet + 64, buff, totalCount);
    header = (struct Header*) (packet + 64 + totalCount);
    createHeader(header , 0, 1, SHA256, FLUSH, 0, 256/64);
    changeEndian((unsigned char *)header, 64);
    memcpy(packet + 64 + totalCount + 64, whitener, 256);
    
    //printf("%x %d : ", mode, totalCount + 64 + 256 + 64);
    //printBuff(packet, totalCount + 64); // + 256 + 64);
    //changeEndian((unsigned char *)packet, totalCount + 64 + 256 + 64);
    if (!debug){
        write_from_buffer(fdh2c, (char *)packet, totalCount + 64 + 256 + 64, 0);
    }
}

int getPacket(unsigned char * buff){
    unsigned char *packet = (unsigned char*) malloc(sizeof(unsigned char)*(64));
    printf("readResponse\n");
    if (debug){
        
    }
    else{
        fdc2h = openChannel(channelc2h);
        read_to_buffer(fdc2h, (char *)packet, 64, 0);
        closeChannel(fdc2h);
        
        memcpy(buff, packet + 32, 32);
        //changeEndian((unsigned char *)buff, 32);
        printBuff(buff, 32); 
    }
}

static int crypto_engine_sha256_init(EVP_MD_CTX *ctx) {
    fdh2c = openChannel(channelh2c);
    if(fdh2c){
        //printf("fdh2c Opened !!\n");
    }
    else{
        printf("Error occured !!\n");
    }
    printf("init called\n");
    padblock = (unsigned char*) malloc(sizeof(unsigned char)*128);
    padblockOffset = 0; 
    initialised = 1;
    return 1;
}

static int crypto_engine_sha256_update(EVP_MD_CTX *ctx,const void *data,size_t count) 
{
    int i, j, k, bufferCount;
    unsigned char * buffer = (unsigned char *)data;
    unsigned char * testbuffer;
    unsigned char *response = (unsigned char*) malloc(sizeof(unsigned char)*(64));
    printf("update called\n", i);    
    totalCount += count; 
    bufferCount = 0;
    for (i=-1; i <= bufferCount; i++){            
        if(i == -1){
            if(padblockOffset){
                memcpy(padblock + padblockOffset, buffer, 64-padblockOffset);
                buffer = buffer - 64 + padblockOffset;
                bufferCount = (count - 64 + padblockOffset)/64;
                sendPacket(padblock, 64, HASH_CONTINUE);
                getPacket(response);
            }
            else{
                bufferCount = count/64;
            }
        }
        else if(i == bufferCount){
            memcpy(padblock, &buffer[bufferCount*64], count%64);
            memcpy(padblock + count%64, whitener, 64 - count%64);            
            padblockOffset = count%64;
        }
        else{
            //printf("%d\n", bufferCount-i);
            if (bufferCount-i >= 128){
               k = 128; 
            }
            else{
                k = bufferCount-i;
            }
            if (initialised == 1){
                initialised ++;
                sendPacket((unsigned char *)buffer + 64*i, 64*k, HASH_INIT);
                getPacket(response);
            }
            else{
                sendPacket((unsigned char *)buffer + 64*i, 64*k, HASH_CONTINUE);
                getPacket(response);
            }
            i += k-1;
        }        
    }       
    return 1;
}

static int crypto_engine_sha256_final(EVP_MD_CTX *ctx,unsigned char *md) {
    int bcount;
    printf("final called\n");
    bcount = calculatePadding(padblock, totalCount);
    if (initialised == 1){
        sendPacket(padblock, 64*bcount, HASH);
    }
    else {
        sendPacket(padblock, 64*bcount, HASH_FINAL);
    }
    sendPacket(whitener, 256, FLUSH);
    
    getPacket(md);
    
    //read_to_buffer(channelc2h, fdc2h, md, 32, 0);
    //printf("SHA256 final size of EVP_MD: %d\n", sizeof(EVP_MD));
    //memcpy(md,(unsigned char*)ctx->md_data,32);
    
    free(padblock);
    
    if(fdc2h){
        closeChannel(fdc2h);
        //printf("fdc2h Closed !!\n");
    }
    if(fdh2c){
        closeChannel(fdh2c);
        //printf("fdh2c Closed !!\n");
    }
    return 1;
}

static void init(void)
{
  //memcpy(&digest_md5, EVP_md5(), sizeof(EVP_MD));
  digest_sha256.init = crypto_engine_sha256_init;
  digest_sha256.update = crypto_engine_sha256_update;
  digest_sha256.final = crypto_engine_sha256_final;
  digest_sha256.block_size = 64;   /* Internal blocksize, see rfc1321/md5.h */
  digest_sha256.ctx_size = sizeof(SHA_CTX);
};


static int digest_nids[] = { NID_sha256, 0 };

static int digests(ENGINE *e, const EVP_MD **digest, const int **nids, int nid)
{
    int ok = 1;
    if (!digest) {
        /* We are returning a list of supported nids */
        *nids = digest_nids;
        return (sizeof(digest_nids) - 1) / sizeof(digest_nids[0]);
    }
    /* We are being asked for a specific digest */
    switch (nid) {
        case NID_sha256:
            *digest = &digest_sha256;
            break;
        default:
            ok = 0;
            *digest = NULL;
            break;
    }
    return ok;
}

static const char *engine_id = "cryptHdl";
static const char *engine_name = "A SHA256 engine for FPGA accelerated hardware\n";
static int bind(ENGINE *e, const char *id)
{
    int ret = 0;
    static int loaded = 0;
    
    if (id && strcmp(id, engine_id)) {
        fprintf(stderr, "cryptHdl engine called with the unexpected id %s\n", id);
        fprintf(stderr, "The expected id is %s\n", engine_id);
        goto end;
    }

    if (loaded) {
        fprintf(stderr, "cryptHdl engine already loaded\n");
        goto end;
    }
    loaded = 1;
    
    if (!ENGINE_set_id(e, engine_id)) {
        fprintf(stderr, "ENGINE_set_id failed\n");
        goto end;
    }
    if (!ENGINE_set_name(e, engine_name)) {
        printf("ENGINE_set_name failed\n");
        goto end;
    }
    if (!ENGINE_set_digests(e, digests)) {
        printf("ENGINE_set_name failed\n");
        goto end;
    }
    init();
    ret = 1;
    end:
    return ret;
}


IMPLEMENT_DYNAMIC_BIND_FN(bind)
IMPLEMENT_DYNAMIC_CHECK_FN()
