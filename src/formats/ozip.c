#include "formats/ozip.h"

#include <stdlib.h>
#include <string.h>

#include "formats/aes.h"
#include "core/util.h"

#define MAGIC "OPPOENCRYPT!"
#define DATA_OFF 0x1050u
#define WHOLE_UNIT 0x4010u
#define SEG_DATA 0x40000u
#define SEG_STRIDE 0x40050u
#define SEG_HDR 0x50u
#define SEG_CHUNK 0x4000u

static const char *const KEYS[] = {
    "D6EECF0AE5ACD4E0E9FE522DE7CE381E", "D6ECCF0AE5ACD4E0E92E522DE7C1381E", "D6DCCF0AD5ACD4E0292E522DB7C1381E",
    "D7DCCE1AD4AFDCE2393E5161CBDC4321", "D7DBCE2AD4ADDCE1393E5521CBDC4321", "D7DBCE1AD4AFDCE1393E5121CBDC4321",
    "D4D2CD61D4AFDCE13B5E01221BD14D20", "261CC7131D7C1481294E532DB752381E", "1CA21E12271335AE33AB81B2A7B14622",
    "D4D2CE11D4AFDCE13B3E0121CBD14D20", "1C4C1EA3A12531AE491B21BB31613C11", "1C4C1EA3A12531AE4A1B21BB31C13C21",
    "1C4A11A3A12513AE441B23BB31513121", "1C4A11A3A12589AE441A23BB31517733", "1C4A11A3A22513AE541B53BB31513121",
    "2442CE821A4F352E33AE81B22BC1462E", "14C2CD6214CFDC2733AE81B22BC1462C", "1E38C1B72D522E29E0D4ACD50ACFDCD6",
    "12341EAAC4C123CE193556A1BBCC232D", "2143DCCB21513E39E1DCAFD41ACEDBD7", "2D23CCBBA1563519CE23C1C4AA1E3412",
    "172B3E14E46F3CE13E2B5121CBDC4321", "ACAA1E12A71431CE4A1B21BBA1C1C6A2", "ACAC1E13A72531AE4A1B22BB31C1CC22",
    "1C4411A3A12533AE441B21BB31613C11", "1C4416A8A42717AE441523B336513121", "55EEAA33112133AE441B23BB31513121",
    "ACAC1E13A12531AE4A1B21BB31C13C21", "ACAC1E13A72431AE4A1B22BBA1C1C6A2", "12CAC11211AAC3AEA2658690122C1E81",
    "1CA21E12271435AE331B81BBA7C14612", "D1DACF24351CE428A9CE32ED87323216", "A1CC75115CAECB890E4A563CA1AC67C8",
    "2132321EA2CA86621A11241ABA512722", "22A21E821743E5EE33AE81B227B1462E", NULL,
};

static aes128 g_aes;
static int g_key = -1;

static void key_bytes(const char *hex, uint8_t out[16])
{
    for (int i = 0; i < 16; i++) {
        unsigned v;
        sscanf(hex + 2 * i, "%2x", &v);
        out[i] = (uint8_t)v;
    }
}

static int plausible(const uint8_t d[16])
{
    static const char *const magics[] = {"PK\3\4", "AVB0", "ANDR", "\x3a\xff\x26\xed", "CrAU", "VNDR", "\x7f" "ELF",
                                         "OPPO", NULL};
    for (int i = 0; magics[i]; i++)
        if (!memcmp(d, magics[i], 4))
            return 1;
    return d[0] == 0x1f && d[1] == 0x8b && d[2] == 8;
}

int ozip_head_is_encrypted(const unsigned char *h, size_t n)
{
    return n >= 12 && !memcmp(h, MAGIC, 12);
}

int ozip_is_encrypted(rsrc *s)
{
    unsigned char h[12];
    return s->size >= 0x60 && rsrc_read(s, h, 12, 0) == 0 && ozip_head_is_encrypted(h, 12);
}

int ozip_have_key(void)
{
    return g_key >= 0;
}

int ozip_find_key(rsrc *s, ozip_kind kind)
{
    uint8_t enc[16], dec[16], key[16];
    uint64_t at = kind == OZIP_SEGMENTED ? SEG_HDR : DATA_OFF;
    if (s->size < at + 16 || rsrc_read(s, enc, 16, at) < 0)
        return 0;
    if (g_key >= 0) {
        aes128_decrypt(&g_aes, enc, dec);
        if (plausible(dec))
            return 1;
    }
    for (int i = 0; KEYS[i]; i++) {
        aes128 a;
        key_bytes(KEYS[i], key);
        aes128_init(&a, key);
        aes128_decrypt(&a, enc, dec);
        if (plausible(dec)) {
            g_aes = a;
            if (g_key != i)
                debug("ozip: AES key %s", KEYS[i]);
            g_key = i;
            return 1;
        }
    }
    return 0;
}

typedef struct {
    rsrc *base;
    ozip_kind kind;
    aes128 aes;
    unsigned char *tmp;
} ozip_priv;

#define TMP_SIZE (1u << 20)

static int ozip_pread(rsrc *s, void *buf, size_t len, uint64_t off)
{
    ozip_priv *p = s->priv;
    unsigned char *b = buf;
    if (off > s->size || len > s->size - off) {
        memset(buf, 0, len);
        return -1;
    }
    if (p->kind == OZIP_MEMBER) {
        while (len) {
            uint64_t a = off & ~(uint64_t)15;
            size_t span = (size_t)((off + len + 15) / 16 * 16 - a);
            if (span > TMP_SIZE)
                span = TMP_SIZE;
            uint64_t avail = p->base->size - DATA_OFF - a;
            size_t got = span <= avail ? span : (size_t)avail;
            if (rsrc_read(p->base, p->tmp, got, DATA_OFF + a) < 0)
                return -1;
            for (size_t k = 0; k + 16 <= got; k += 16)
                aes128_decrypt(&p->aes, p->tmp + k, p->tmp + k);
            size_t skip = (size_t)(off - a);
            size_t take = got - skip < len ? got - skip : len;
            if (!take)
                return -1;
            memcpy(b, p->tmp + skip, take);
            b += take;
            off += take;
            len -= take;
        }
        return 0;
    }
    while (len) {
        uint64_t raw, pos, run;
        if (p->kind == OZIP_WHOLE) {
            pos = off % WHOLE_UNIT;
            raw = DATA_OFF + off;
            run = WHOLE_UNIT - pos;
        } else {
            uint64_t seg = off / SEG_DATA, w = off % SEG_DATA;
            pos = w % SEG_CHUNK;
            raw = seg * SEG_STRIDE + SEG_HDR + w;
            run = SEG_CHUNK - pos;
        }
        if (pos < 16 && raw - pos + 16 <= p->base->size) {
            uint8_t blk[16];
            if (rsrc_read(p->base, blk, 16, raw - pos) < 0)
                return -1;
            aes128_decrypt(&p->aes, blk, blk);
            size_t take = 16 - (size_t)pos < len ? 16 - (size_t)pos : len;
            memcpy(b, blk + pos, take);
            b += take;
            off += take;
            len -= take;
            continue;
        }
        size_t take = run < len ? (size_t)run : len;
        if (rsrc_read(p->base, b, take, raw) < 0)
            return -1;
        b += take;
        off += take;
        len -= take;
    }
    return 0;
}

static void ozip_close(rsrc *s)
{
    ozip_priv *p = s->priv;
    rsrc_close(p->base);
    free(p->tmp);
    free(p);
}

static int64_t header_size(rsrc *base, uint64_t at)
{
    unsigned char h[32];
    if (at + 0x20 > base->size || rsrc_read(base, h, 32, at) < 0 || memcmp(h, MAGIC, 12))
        return -1;
    char num[17];
    memcpy(num, h + 16, 16);
    num[16] = 0;
    char *end;
    long long v = strtoll(num, &end, 10);
    if (end == num || v < 0)
        return -1;
    return v;
}

rsrc *ozip_open(rsrc *base, ozip_kind kind, const char *label, char *err, size_t errlen)
{
    uint64_t size;
    if (kind == OZIP_WHOLE) {
        if (base->size <= DATA_OFF) {
            snprintf(err, errlen, "%s: truncated .ozip", label);
            return NULL;
        }
        size = base->size - DATA_OFF;
    } else if (kind == OZIP_MEMBER) {
        int64_t d = header_size(base, 0);
        if (d < 0 || (uint64_t)d > base->size - DATA_OFF) {
            snprintf(err, errlen, "%s: corrupt OPPO encryption header", label);
            return NULL;
        }
        size = (uint64_t)d;
    } else {
        size = 0;
        for (uint64_t at = 0;; at += SEG_STRIDE) {
            int64_t d = header_size(base, at);
            if (d < 0) {
                snprintf(err, errlen, "%s: corrupt OPPO encryption segment at %llu", label, (unsigned long long)at);
                return NULL;
            }
            if ((uint64_t)d > SEG_DATA)
                d = SEG_DATA;
            size += (uint64_t)d;
            if ((uint64_t)d < SEG_DATA || at + SEG_STRIDE >= base->size)
                break;
        }
    }
    if (!ozip_find_key(base, kind) && g_key < 0) {
        snprintf(err, errlen,
                 "%s: encrypted with an AES key that is not among the published OPPO/realme keys; it cannot be "
                 "decrypted (use a non-encrypted OTA or fastboot package of the same build instead)",
                 label);
        return NULL;
    }
    ozip_priv *p = xcalloc(1, sizeof *p);
    p->base = base;
    p->kind = kind;
    p->aes = g_aes;
    p->tmp = xmalloc(TMP_SIZE);
    rsrc *s = xcalloc(1, sizeof *s);
    s->priv = p;
    s->size = size;
    s->name = xasprintf("%s (decrypted)", label);
    s->pread = ozip_pread;
    s->close = ozip_close;
    return s;
}
