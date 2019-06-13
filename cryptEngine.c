#include <stdio.h>
#include <string.h>
#include <openssl/engine.h>
#include <openssl/evp.h>
#include "xdma/cxdma.h"
static EVP_MD digest_sha256;

static char *device = "/dev/xdma0_control";
static int fd;
static unsigned long _base;

static int crypto_engine_sha256_init(EVP_MD_CTX *ctx) {
    fd = openDev(device);
    if(fd){
        printf("Device Opened !!\n");
    }
    else{
        printf("Error occured !!\n");
    }    

    printf("init called\n");
    return 1;
}

static int crypto_engine_sha256_update(EVP_MD_CTX *ctx,const void *data,size_t count) 
{
    printf("update called\n");
    //unsigned char * digest256 = (unsigned char*) malloc(sizeof(unsigned char)*32);
    //memset(digest256,2,32);
    //count = 32;
    //ctx->md_data = digest256;
    return 1;
}

static int crypto_engine_sha256_final(EVP_MD_CTX *ctx,unsigned char *md) {
    printf("final called\n");
    //printf("SHA256 final size of EVP_MD: %d\n", sizeof(EVP_MD));
    //memcpy(md,(unsigned char*)ctx->md_data,32);
    if(fd){
        closeDev(fd);  
        printf("Device Closed !!\n");
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
static const char *engine_name = "A SHA256 engine for FPGA accelerated hardware";
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
