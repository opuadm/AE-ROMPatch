#ifndef AEP_AES_H
#define AEP_AES_H

#include <stdint.h>

typedef struct {
    uint8_t rk[176];
} aes128;

void aes128_init(aes128 *a, const uint8_t key[16]);
void aes128_decrypt(const aes128 *a, const uint8_t in[16], uint8_t out[16]);
void aes128_encrypt(const aes128 *a, const uint8_t in[16], uint8_t out[16]);

#endif
