#define RESET  0x01
#define ECHO   0x02
#define WHO    0x03
#define STATUS 0x04
#define FLUSH  0x05
#define SEARCH 0x09

//ALGO
#define AES    0xAE
#define SHA256 0x23
#define ECC    0xEC
#define ACORN  0xAC
#define RANDOM 0x24

#define HASH           0xB0
#define HASH_INIT      0xB1
#define HASH_CONTINUE  0xB2
#define HASH_FINAL     0xB3
#define HASH_STATESET  0xB4
#define HASH_POW       0xB5
#define GENBITS        0xB6

#define SYNC   0xAFAF


#define PKTSYNCPTR     0
#define SOURCEPTR      8
#define SINCPTR        16
#define LENPTR         24
#define ALGOPTR        40
#define MODEPTR        48
#define PKTIDPTR       56
#define ACKREQUEST_PTR 47

struct Header
{
    short sync;
    unsigned char src;
    unsigned char sink;
    short length;
    unsigned char algo;
    unsigned char mode;
    unsigned char pktid;
    unsigned char reserved[54];
};

extern int createHeader(struct Header *header, int src, int sink, int algo, int mode, int pktid, int length);