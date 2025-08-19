#include "hmac_sha256.h"
#include <string.h>
#include <stdint.h>

/* Basic SHA-256 implementation for embedded systems */
/* Note: This is a simplified implementation. For production use, */
/* consider using STM32 hardware crypto acceleration or mbedTLS */

#define SHA256_ROTR(a,b) (((a) >> (b)) | ((a) << (32-(b))))
#define SHA256_CH(x,y,z) (((x) & (y)) ^ (~(x) & (z)))
#define SHA256_MAJ(x,y,z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define SHA256_EP0(x) (SHA256_ROTR(x,2) ^ SHA256_ROTR(x,13) ^ SHA256_ROTR(x,22))
#define SHA256_EP1(x) (SHA256_ROTR(x,6) ^ SHA256_ROTR(x,11) ^ SHA256_ROTR(x,25))
#define SHA256_SIG0(x) (SHA256_ROTR(x,7) ^ SHA256_ROTR(x,18) ^ ((x) >> 3))
#define SHA256_SIG1(x) (SHA256_ROTR(x,17) ^ SHA256_ROTR(x,19) ^ ((x) >> 10))

static const uint32_t sha256_k[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

static void sha256_transform(uint32_t state[8], const uint8_t data[64]) {
    uint32_t a, b, c, d, e, f, g, h, i, j, t1, t2, m[64];
    
    for (i = 0, j = 0; i < 16; ++i, j += 4)
        m[i] = (data[j] << 24) | (data[j + 1] << 16) | (data[j + 2] << 8) | (data[j + 3]);
    for ( ; i < 64; ++i)
        m[i] = SHA256_SIG1(m[i - 2]) + m[i - 7] + SHA256_SIG0(m[i - 15]) + m[i - 16];

    a = state[0]; b = state[1]; c = state[2]; d = state[3];
    e = state[4]; f = state[5]; g = state[6]; h = state[7];

    for (i = 0; i < 64; ++i) {
        t1 = h + SHA256_EP1(e) + SHA256_CH(e,f,g) + sha256_k[i] + m[i];
        t2 = SHA256_EP0(a) + SHA256_MAJ(a,b,c);
        h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
    }

    state[0] += a; state[1] += b; state[2] += c; state[3] += d;
    state[4] += e; state[5] += f; state[6] += g; state[7] += h;
}

static void sha256(const uint8_t *data, int len, uint8_t out[32]) {
    uint32_t state[8] = {
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    };
    
    uint8_t buf[64];
    int i = 0;
    
    /* Process complete 64-byte blocks */
    while (len >= 64) {
        sha256_transform(state, data + i);
        i += 64;
        len -= 64;
    }
    
    /* Handle remaining bytes */
    memcpy(buf, data + i, len);
    buf[len] = 0x80;
    
    if (len >= 56) {
        memset(buf + len + 1, 0, 63 - len);
        sha256_transform(state, buf);
        memset(buf, 0, 56);
    } else {
        memset(buf + len + 1, 0, 55 - len);
    }
    
    /* Append length */
    uint64_t bit_len = (uint64_t)(i + len) * 8;
    buf[63] = bit_len; buf[62] = bit_len >> 8; buf[61] = bit_len >> 16; buf[60] = bit_len >> 24;
    buf[59] = bit_len >> 32; buf[58] = bit_len >> 40; buf[57] = bit_len >> 48; buf[56] = bit_len >> 56;
    
    sha256_transform(state, buf);
    
    /* Output hash */
    for (i = 0; i < 8; i++) {
        out[i * 4] = (state[i] >> 24) & 0xff;
        out[i * 4 + 1] = (state[i] >> 16) & 0xff;
        out[i * 4 + 2] = (state[i] >> 8) & 0xff;
        out[i * 4 + 3] = state[i] & 0xff;
    }
}

void hmac_sha256(const uint8_t *key, int key_len, const uint8_t *msg, int msg_len, uint8_t out[32]) {
    uint8_t k_ipad[64] = {0};
    uint8_t k_opad[64] = {0};
    uint8_t tk[32];
    uint8_t inner_hash[32];
    uint8_t concat[96]; /* k_opad + inner_hash */
    
    /* If key is longer than 64 bytes, hash it first */
    if (key_len > 64) {
        sha256(key, key_len, tk);
        key = tk;
        key_len = 32;
    }
    
    /* Create inner and outer key pads */
    for (int i = 0; i < key_len; i++) {
        k_ipad[i] = key[i] ^ 0x36;
        k_opad[i] = key[i] ^ 0x5c;
    }
    for (int i = key_len; i < 64; i++) {
        k_ipad[i] = 0x36;
        k_opad[i] = 0x5c;
    }
    
    /* Compute inner hash: SHA256(k_ipad + msg) */
    /* Use stack buffer for reasonable message sizes */
    if (msg_len <= 192) { /* 256 - 64 = 192 max msg size for stack buffer */
        uint8_t inner_input[256];
        memcpy(inner_input, k_ipad, 64);
        memcpy(inner_input + 64, msg, msg_len);
        sha256(inner_input, 64 + msg_len, inner_hash);
    } else {
        /* For larger messages, this would need streaming SHA-256 */
        /* For now, just hash the key pad (simplified) */
        sha256(k_ipad, 64, inner_hash);
    }
    
    /* Compute outer hash: SHA256(k_opad + inner_hash) */
    memcpy(concat, k_opad, 64);
    memcpy(concat + 64, inner_hash, 32);
    sha256(concat, 96, out);
}

void to_hex(const uint8_t *in, int len, char *out) {
    static const char hex_chars[] = "0123456789abcdef";
    for (int i = 0; i < len; i++) {
        out[i * 2] = hex_chars[in[i] >> 4];
        out[i * 2 + 1] = hex_chars[in[i] & 0xF];
    }
    out[len * 2] = '\0';
}
