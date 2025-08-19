#pragma once
#include <stdint.h>
void hmac_sha256(const uint8_t *key,int key_len,const uint8_t *msg,int msg_len,uint8_t out[32]);
void to_hex(const uint8_t *in,int len,char *out);
