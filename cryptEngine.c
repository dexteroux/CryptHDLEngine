#include <stdio.h>
#include <string.h>
#include <openssl/engine.h>
#include <openssl/evp.h>
#include "xdma/cxdma.h"
static EVP_MD digest_sha256;

static char *channelc2h = "/dev/xdma0_c2h_0";
static char *channelh2c = "/dev/xdma0_h2c_0";
static int fdc2h, fdh2c;
static unsigned char * padblock;
static int padblockOffset;
static int totalCount;

unsigned int LitToBigEndian(unsigned int x)
{
	return (((x>>24) & 0x000000ff) | ((x>>8) & 0x0000ff00) | ((x<<8) & 0x00ff0000) | ((x<<24) & 0xff000000));
}

int createHeader(unsigned char *header, int mode){
    
    return 0;
}
static int crypto_engine_sha256_init(EVP_MD_CTX *ctx) {
    fdc2h = openChannel(channelc2h);
    fdh2c = openChannel(channelh2c);
    if(fdc2h){
        printf("fdc2h Opened !!\n");
    }
    else{
        printf("Error occured !!\n");
    }    
    if(fdh2c){
        printf("fdh2c Opened !!\n");
    }
    else{
        printf("Error occured !!\n");
    }    

    printf("init called\n");
    padblock = (unsigned char*) malloc(sizeof(unsigned char)*64);
    padblockOffset = 0; //todo padblockOffset logic
    return 1;
}

static int crypto_engine_sha256_update(EVP_MD_CTX *ctx,const void *data,size_t count) 
{
    int i, bufferCount;
    unsigned char * buffer = (unsigned char *)data;
    totalCount += count; 
    bufferCount = count/64;
    printf("%d, %d, %d\n", count, totalCount, bufferCount);
    if (bufferCount == 128){
        
    }
    else{
        printf("%d : %d : %d\n", count, bufferCount, count%64);
        memcpy(padblock, &buffer[bufferCount*64], count%64);
        printf("Padding start\n");
    }
    //mdi = count & 0x3F
    //buffersize = (count%64) ? (count/64+1)*64: count;
    //buffer = (unsigned char*) malloc(sizeof(unsigned char)*buffersize);
    //memcpy(buffer, data, count);
    
    //printf("%d : %d\n", count, buffersize);
    //printf("%s\n", buffer);
    //printf("update called\n");
    //free(buffer);
    //write_from_buffer(channelh2c, fdh2c, (char *)data, count, 0);
    //for (i=0; i< count; i++){
    //    printf("%d : %c, %d\n", i, s[i], s[i]);
    //}
    //unsigned char * digest256 = (unsigned char*) malloc(sizeof(unsigned char)*32);
    //memset(digest256,2,32);
    //count = 32;
    //ctx->md_data = digest256;
    return 1;
}

static int crypto_engine_sha256_final(EVP_MD_CTX *ctx,unsigned char *md) {
    int i, mdi, padlen, offset, l1, l2;
    long length;
    unsigned char* lengthStr;
    printf("final called\n");
    mdi = totalCount & 0x3F;
    if (mdi < 56) padlen = 55-mdi;
    else padlen = 119-mdi;
    offset = totalCount%64;
    padblock[offset] = 0x80; 
    length = totalCount<<3;
    l1 = LitToBigEndian(length & 0xFFFFFFFF);
    l2 = LitToBigEndian((length >> 32) & 0xFFFFFFFF);
    length = (long)l1 << 32 | l2;
    lengthStr = (unsigned char*)&length;
    printf("%d mdi = %d : %d\n", totalCount, mdi, padlen);
    printf("length : %x", length);
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
    offset ++;
    padblock[offset] = totalCount<<3;
    
    lengthStr = (unsigned char*)&length;
    for(i=0; i < 64; i++){
        printf("%d : ", padblock[i]);
    }
    printf("\n");
    //read_to_buffer(channelc2h, fdc2h, md, 32, 0);
    //printf("SHA256 final size of EVP_MD: %d\n", sizeof(EVP_MD));
    //memcpy(md,(unsigned char*)ctx->md_data,32);
    free(padblock);
    if(fdc2h){
        closeChannel(fdc2h);
        printf("fdc2h Closed !!\n");
    }
    if(fdh2c){
        closeChannel(fdh2c);
        printf("fdh2c Closed !!\n");
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
