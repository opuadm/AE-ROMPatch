#include "formats/aes.h"

#include <string.h>

static uint8_t sbox[256], inv_sbox[256], m9[256], m11[256], m13[256], m14[256];
static int tables_ready;

static uint8_t xt(uint8_t x)
{
    return (uint8_t)((x << 1) ^ ((x & 0x80) ? 0x1b : 0));
}

static uint8_t mul(uint8_t a, uint8_t b)
{
    uint8_t r = 0;
    while (b) {
        if (b & 1)
            r ^= a;
        a = xt(a);
        b >>= 1;
    }
    return r;
}

static void build_tables(void)
{
    uint8_t p = 1, q = 1;
    do {
        p = (uint8_t)(p ^ (p << 1) ^ ((p & 0x80) ? 0x1b : 0));
        q ^= (uint8_t)(q << 1);
        q ^= (uint8_t)(q << 2);
        q ^= (uint8_t)(q << 4);
        if (q & 0x80)
            q ^= 0x09;
        uint8_t x = (uint8_t)(q ^ (uint8_t)((q << 1) | (q >> 7)) ^ (uint8_t)((q << 2) | (q >> 6)) ^
                              (uint8_t)((q << 3) | (q >> 5)) ^ (uint8_t)((q << 4) | (q >> 4)));
        sbox[p] = (uint8_t)(x ^ 0x63);
    } while (p != 1);
    sbox[0] = 0x63;
    for (int i = 0; i < 256; i++) {
        inv_sbox[sbox[i]] = (uint8_t)i;
        m9[i] = mul((uint8_t)i, 9);
        m11[i] = mul((uint8_t)i, 11);
        m13[i] = mul((uint8_t)i, 13);
        m14[i] = mul((uint8_t)i, 14);
    }
    tables_ready = 1;
}

void aes128_init(aes128 *a, const uint8_t key[16])
{
    if (!tables_ready)
        build_tables();
    memcpy(a->rk, key, 16);
    uint8_t rcon = 1;
    for (int i = 16; i < 176; i += 4) {
        uint8_t t[4];
        memcpy(t, a->rk + i - 4, 4);
        if (i % 16 == 0) {
            uint8_t u = t[0];
            t[0] = (uint8_t)(sbox[t[1]] ^ rcon);
            t[1] = sbox[t[2]];
            t[2] = sbox[t[3]];
            t[3] = sbox[u];
            rcon = xt(rcon);
        }
        for (int k = 0; k < 4; k++)
            a->rk[i + k] = (uint8_t)(a->rk[i - 16 + k] ^ t[k]);
    }
}

static void add_key(uint8_t s[16], const uint8_t *k)
{
    for (int i = 0; i < 16; i++)
        s[i] ^= k[i];
}

void aes128_encrypt(const aes128 *a, const uint8_t in[16], uint8_t out[16])
{
    uint8_t s[16], t[16];
    memcpy(s, in, 16);
    add_key(s, a->rk);
    for (int r = 1; r <= 10; r++) {
        for (int i = 0; i < 16; i++)
            t[i] = sbox[s[(i + 4 * (i % 4)) % 16]];
        if (r < 10) {
            for (int c = 0; c < 4; c++) {
                uint8_t *m = t + 4 * c, a0 = m[0], a1 = m[1], a2 = m[2], a3 = m[3];
                m[0] = (uint8_t)(xt(a0) ^ xt(a1) ^ a1 ^ a2 ^ a3);
                m[1] = (uint8_t)(a0 ^ xt(a1) ^ xt(a2) ^ a2 ^ a3);
                m[2] = (uint8_t)(a0 ^ a1 ^ xt(a2) ^ xt(a3) ^ a3);
                m[3] = (uint8_t)(xt(a0) ^ a0 ^ a1 ^ a2 ^ xt(a3));
            }
        }
        memcpy(s, t, 16);
        add_key(s, a->rk + 16 * r);
    }
    memcpy(out, s, 16);
}

void aes128_decrypt(const aes128 *a, const uint8_t in[16], uint8_t out[16])
{
    uint8_t s[16], t[16];
    memcpy(s, in, 16);
    add_key(s, a->rk + 160);
    for (int r = 9; r >= 0; r--) {
        for (int i = 0; i < 16; i++)
            t[(i + 4 * (i % 4)) % 16] = inv_sbox[s[i]];
        memcpy(s, t, 16);
        add_key(s, a->rk + 16 * r);
        if (r > 0) {
            for (int c = 0; c < 4; c++) {
                uint8_t *m = s + 4 * c, a0 = m[0], a1 = m[1], a2 = m[2], a3 = m[3];
                m[0] = (uint8_t)(m14[a0] ^ m11[a1] ^ m13[a2] ^ m9[a3]);
                m[1] = (uint8_t)(m9[a0] ^ m14[a1] ^ m11[a2] ^ m13[a3]);
                m[2] = (uint8_t)(m13[a0] ^ m9[a1] ^ m14[a2] ^ m11[a3]);
                m[3] = (uint8_t)(m11[a0] ^ m13[a1] ^ m9[a2] ^ m14[a3]);
            }
        }
    }
    memcpy(out, s, 16);
}
