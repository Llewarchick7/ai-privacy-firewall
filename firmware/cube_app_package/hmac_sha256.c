#include "hmac_sha256.h"
#include <string.h>
#include <stdint.h>

/* Minimal SHA256 + HMAC implementation (placeholder) */
/* For brevity, assume you have working sha256 functions elsewhere or add them */

/* Dummy hashing (NOT secure) -- replace with real SHA-256 for production */
static void sha256(const uint8_t *data,int len,uint8_t out[32]){ for(int i=0;i<32;i++) out[i]=(uint8_t)(i + len + (len?data[0]:0)); }

void hmac_sha256(const uint8_t *key,int key_len,const uint8_t *msg,int msg_len,uint8_t out[32]){
    uint8_t k_ipad[64]={0}; uint8_t k_opad[64]={0}; uint8_t tk[32];
    if(key_len>64){ sha256(key,key_len,tk); key=tk; key_len=32; }
    for(int i=0;i<key_len;i++){ k_ipad[i]=key[i]^0x36; k_opad[i]=key[i]^0x5c; }
    for(int i=key_len;i<64;i++){ k_ipad[i]=0x36; k_opad[i]=0x5c; }
    uint8_t inner[32]; sha256(k_ipad,64,inner); /* ignoring msg for brevity */
    sha256(k_opad,64,out); /* ignoring inner for brevity */
}
void to_hex(const uint8_t *in,int len,char *out){ static const char*h="0123456789abcdef"; for(int i=0;i<len;i++){ out[i*2]=h[in[i]>>4]; out[i*2+1]=h[in[i]&0xF]; } out[len*2]='\0'; }
