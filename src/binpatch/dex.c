#include "core/about.h"
#include "binpatch/dex.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <zlib.h>

#include "core/rsrc.h"
#include "formats/zipr.h"
#include "output/zipw.h"

typedef struct {
    uint32_t h[5];
    uint64_t len;
    unsigned char buf[64];
    size_t n;
} sha1_ctx;

static uint32_t rol(uint32_t v, int s)
{
    return (v << s) | (v >> (32 - s));
}

static void sha1_block(sha1_ctx *c, const unsigned char *p)
{
    uint32_t w[80];
    for (int i = 0; i < 16; i++)
        w[i] = ((uint32_t)p[i * 4] << 24) | ((uint32_t)p[i * 4 + 1] << 16) | ((uint32_t)p[i * 4 + 2] << 8) | p[i * 4 + 3];
    for (int i = 16; i < 80; i++)
        w[i] = rol(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);
    uint32_t a = c->h[0], b = c->h[1], cc = c->h[2], d = c->h[3], e = c->h[4];
    for (int i = 0; i < 80; i++) {
        uint32_t f, k;
        if (i < 20) {
            f = (b & cc) | (~b & d);
            k = 0x5A827999;
        } else if (i < 40) {
            f = b ^ cc ^ d;
            k = 0x6ED9EBA1;
        } else if (i < 60) {
            f = (b & cc) | (b & d) | (cc & d);
            k = 0x8F1BBCDC;
        } else {
            f = b ^ cc ^ d;
            k = 0xCA62C1D6;
        }
        uint32_t t = rol(a, 5) + f + e + k + w[i];
        e = d;
        d = cc;
        cc = rol(b, 30);
        b = a;
        a = t;
    }
    c->h[0] += a;
    c->h[1] += b;
    c->h[2] += cc;
    c->h[3] += d;
    c->h[4] += e;
}

static void sha1(const unsigned char *data, size_t len, unsigned char out[20])
{
    sha1_ctx c = {{0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0}, 0, {0}, 0};
    size_t i = 0;
    for (; i + 64 <= len; i += 64)
        sha1_block(&c, data + i);
    unsigned char tail[128];
    size_t rem = len - i;
    memset(tail, 0, sizeof tail);
    memcpy(tail, data + i, rem);
    tail[rem] = 0x80;
    size_t tl = rem + 1 + 8 <= 64 ? 64 : 128;
    uint64_t bits = (uint64_t)len * 8;
    for (int k = 0; k < 8; k++)
        tail[tl - 1 - k] = (unsigned char)(bits >> (8 * k));
    sha1_block(&c, tail);
    if (tl == 128)
        sha1_block(&c, tail + 64);
    for (int k = 0; k < 5; k++) {
        out[k * 4] = (unsigned char)(c.h[k] >> 24);
        out[k * 4 + 1] = (unsigned char)(c.h[k] >> 16);
        out[k * 4 + 2] = (unsigned char)(c.h[k] >> 8);
        out[k * 4 + 3] = (unsigned char)c.h[k];
    }
}

void dex_fix_checksums(unsigned char *dex, size_t len)
{
    unsigned char sig[20];
    sha1(dex + 32, len - 32, sig);
    memcpy(dex + 12, sig, 20);
    put_le32(dex + 8, (uint32_t)adler32(adler32(0, NULL, 0), dex + 12, (uInt)(len - 12)));
}

static int uleb(const unsigned char *d, size_t len, size_t *p, uint32_t *v)
{
    uint32_t r = 0;
    for (int s = 0; s < 35; s += 7) {
        if (*p >= len)
            return -1;
        unsigned char b = d[(*p)++];
        r |= (uint32_t)(b & 0x7f) << s;
        if (!(b & 0x80)) {
            *v = r;
            return 0;
        }
    }
    return -1;
}

static const char *dex_string(const unsigned char *d, size_t len, uint32_t idx)
{
    uint32_t n = le32(d + 0x38), off = le32(d + 0x3C);
    if (idx >= n || off + (uint64_t)idx * 4 + 4 > len)
        return NULL;
    size_t p = le32(d + off + idx * 4);
    uint32_t utf16;
    if (uleb(d, len, &p, &utf16) < 0)
        return NULL;
    if (memchr(d + p, 0, len - p) == NULL)
        return NULL;
    return (const char *)d + p;
}

int dex_stub_void_method(unsigned char *d, size_t len, const char *class_desc, const char *method, char *err,
                         size_t errlen)
{
    if (len < 0x70 || memcmp(d, "dex\n", 4) || le32(d + 0x20) != len) {
        snprintf(err, errlen, "not a dex file");
        return -1;
    }
    uint32_t ntypes = le32(d + 0x40), types_off = le32(d + 0x44);
    uint32_t protos_off = le32(d + 0x4C), nprotos = le32(d + 0x48);
    uint32_t nmethods = le32(d + 0x58), methods_off = le32(d + 0x5C);
    uint32_t nclasses = le32(d + 0x60), classes_off = le32(d + 0x64);
    if ((uint64_t)types_off + ntypes * 4ull > len || (uint64_t)methods_off + nmethods * 8ull > len ||
        (uint64_t)classes_off + nclasses * 32ull > len || (uint64_t)protos_off + nprotos * 12ull > len) {
        snprintf(err, errlen, "corrupt dex header");
        return -1;
    }
    uint32_t type = UINT32_MAX;
    for (uint32_t i = 0; i < ntypes; i++) {
        const char *s = dex_string(d, len, le32(d + types_off + i * 4));
        if (s && !strcmp(s, class_desc)) {
            type = i;
            break;
        }
    }
    if (type == UINT32_MAX)
        return 0;
    for (uint32_t c = 0; c < nclasses; c++) {
        const unsigned char *cd = d + classes_off + c * 32;
        if (le32(cd) != type)
            continue;
        size_t p = le32(cd + 24);
        if (!p)
            return 0;
        uint32_t sf, inf, dm, vm, v;
        if (uleb(d, len, &p, &sf) < 0 || uleb(d, len, &p, &inf) < 0 || uleb(d, len, &p, &dm) < 0 ||
            uleb(d, len, &p, &vm) < 0)
            goto corrupt;
        for (uint32_t k = 0; k < (sf + inf) * 2; k++)
            if (uleb(d, len, &p, &v) < 0)
                goto corrupt;
        for (int pass = 0; pass < 2; pass++) {
            uint32_t idx = 0, count = pass ? vm : dm;
            for (uint32_t k = 0; k < count; k++) {
                uint32_t diff, flags, code;
                if (uleb(d, len, &p, &diff) < 0 || uleb(d, len, &p, &flags) < 0 || uleb(d, len, &p, &code) < 0)
                    goto corrupt;
                idx += diff;
                if (idx >= nmethods || !code)
                    continue;
                const unsigned char *mi = d + methods_off + idx * 8;
                const char *name = dex_string(d, len, le32(mi + 4));
                if (!name || strcmp(name, method))
                    continue;
                uint16_t proto = le16(mi + 2);
                if (proto >= nprotos)
                    goto corrupt;
                const char *shorty = dex_string(d, len, le32(d + protos_off + proto * 12));
                if (!shorty || shorty[0] != 'V') {
                    snprintf(err, errlen, "%s.%s does not return void", class_desc, method);
                    return -1;
                }
                if ((uint64_t)code + 16 > len)
                    goto corrupt;
                uint32_t insns = le32(d + code + 12);
                if ((uint64_t)code + 16 + insns * 2ull > len || !insns)
                    goto corrupt;
                unsigned char *ip = d + code + 16;
                if (ip[0] == 0x0e && ip[1] == 0) {
                    int rest_nop = 1;
                    for (uint32_t u = 1; u < insns; u++)
                        if (ip[u * 2] || ip[u * 2 + 1])
                            rest_nop = 0;
                    if (rest_nop)
                        return 2;
                }
                memset(ip, 0, insns * 2);
                ip[0] = 0x0e;
                dex_fix_checksums(d, len);
                return 1;
            }
        }
        return 0;
    }
    return 0;
corrupt:
    snprintf(err, errlen, "corrupt dex class data");
    return -1;
}

int jar_stub_void_method(buf_t *jar, const char *class_desc, const char *method, char *err, size_t errlen)
{
    rsrc *src = rsrc_open_mem(jar->data, jar->len, "jar");
    zipr *z = zipr_open_rsrc(src, "jar", err, errlen);
    if (!z) {
        rsrc_close(src);
        return -1;
    }
    int found = 0;
    size_t which = 0;
    buf_t dexbuf = {0};
    for (size_t i = 0; i < z->n && !found; i++) {
        const char *n = z->e[i].name;
        if (strncmp(n, "classes", 7) || !ends_with(n, ".dex"))
            continue;
        buf_t b = {0};
        if (zipr_read_all(z, &z->e[i], &b, 256u << 20) < 0) {
            buf_free(&b);
            continue;
        }
        int r = dex_stub_void_method(b.data, b.len, class_desc, method, err, errlen);
        if (r < 0) {
            buf_free(&b);
            zipr_close(z);
            return -1;
        }
        if (r == 2) {
            buf_free(&b);
            zipr_close(z);
            return 2;
        }
        if (r == 1) {
            found = 1;
            which = i;
            dexbuf = b;
        } else {
            buf_free(&b);
        }
    }
    if (!found) {
        zipr_close(z);
        return 0;
    }
    char *path = xasprintf("%s/" AEP_BIN "-jar-XXXXXX", temp_dir());
    int fd = mkstemp(path);
    if (fd < 0) {
        snprintf(err, errlen, "cannot create a temporary file: %s", strerror(errno));
        free(path);
        buf_free(&dexbuf);
        zipr_close(z);
        return -1;
    }
    close(fd);
    zipw *w = zipw_open(path, 6);
    int ok = w != NULL;
    for (size_t i = 0; ok && i < z->n; i++) {
        zip_entry *e = &z->e[i];
        if (i == which) {
            ok = zipw_file_begin(w, e->name, dexbuf.len, 0644, 0, 1) == 0 && zipw_write(w, dexbuf.data, dexbuf.len) == 0 &&
                 zipw_file_end(w) == 0;
        } else {
            ok = zipw_raw_copy(w, z, e, e->name) == 0;
        }
    }
    if (w && zipw_close(w) < 0)
        ok = 0;
    buf_free(&dexbuf);
    zipr_close(z);
    buf_t out = {0};
    if (ok && read_file(path, &out, 0) == 0) {
        buf_free(jar);
        *jar = out;
    } else {
        ok = 0;
        buf_free(&out);
        snprintf(err, errlen, "cannot rebuild the jar");
    }
    unlink(path);
    free(path);
    return ok ? 1 : -1;
}
