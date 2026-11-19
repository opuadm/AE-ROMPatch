#include "formats/tarr.h"

#include <stdlib.h>
#include <string.h>
#include <zlib.h>

#include "core/util.h"

#define BLOCK 512

int tar_probe(const unsigned char *h, size_t n)
{
    if (n < BLOCK || memcmp(h + 257, "ustar", 5))
        return 0;
    unsigned sum = 0;
    for (int i = 0; i < BLOCK; i++)
        sum += (i >= 148 && i < 156) ? ' ' : h[i];
    char num[9];
    memcpy(num, h + 148, 8);
    num[8] = 0;
    return strtoul(num, NULL, 8) == sum;
}

long rsrc_seq_read(void *vctx, void *buf, size_t len)
{
    rsrc_seq *c = vctx;
    if (c->off >= c->end)
        return 0;
    if (len > c->end - c->off)
        len = (size_t)(c->end - c->off);
    if (len > (1u << 20))
        len = 1u << 20;
    if (rsrc_read(c->src, buf, len, c->off) < 0)
        return -1;
    c->off += len;
    return (long)len;
}

static int all_zero(const unsigned char *b)
{
    for (int i = 0; i < BLOCK; i++)
        if (b[i])
            return 0;
    return 1;
}

static int header_ok(const unsigned char *h)
{
    unsigned sum = 0;
    for (int i = 0; i < BLOCK; i++)
        sum += (i >= 148 && i < 156) ? ' ' : h[i];
    char num[9];
    memcpy(num, h + 148, 8);
    num[8] = 0;
    char *end;
    unsigned long v = strtoul(num, &end, 8);
    return end != num && v == sum;
}

static uint64_t field_num(const unsigned char *f, size_t n)
{
    if (f[0] & 0x80) {
        uint64_t v = f[0] & 0x7f;
        for (size_t i = 1; i < n; i++)
            v = (v << 8) | f[i];
        return v;
    }
    char tmp[16];
    size_t l = n < sizeof tmp - 1 ? n : sizeof tmp - 1;
    memcpy(tmp, f, l);
    tmp[l] = 0;
    return strtoull(tmp, NULL, 8);
}

static void pax_parse(const char *d, size_t n, char **path, uint64_t *size, int *have_size)
{
    size_t p = 0;
    while (p < n) {
        char *end;
        unsigned long len = strtoul(d + p, &end, 10);
        if (end == d + p || *end != ' ' || len == 0 || p + len > n)
            return;
        const char *kv = end + 1, *stop = d + p + len - 1;
        const char *eq = memchr(kv, '=', (size_t)(stop - kv));
        if (eq) {
            size_t kl = (size_t)(eq - kv);
            if (kl == 4 && !memcmp(kv, "path", 4)) {
                free(*path);
                *path = xstrndup(eq + 1, (size_t)(stop - eq - 1));
            } else if (kl == 4 && !memcmp(kv, "size", 4)) {
                *size = strtoull(eq + 1, NULL, 10);
                *have_size = 1;
            }
        }
        p += len;
    }
}

typedef struct {
    rsrc *rs;
    uint64_t pos;
    sreader *sr;
} tsrc;

static int t_read(tsrc *t, void *buf, size_t len)
{
    if (t->rs) {
        if (t->pos + len > t->rs->size || rsrc_read(t->rs, buf, len, t->pos) < 0)
            return -1;
        t->pos += len;
        return 0;
    }
    unsigned char *b = buf;
    while (len) {
        long n = sreader_read(t->sr, b, len);
        if (n <= 0)
            return -1;
        b += n;
        len -= (size_t)n;
    }
    return 0;
}

static int t_skip(tsrc *t, uint64_t n)
{
    if (t->rs) {
        t->pos += n;
        return t->pos <= t->rs->size ? 0 : -1;
    }
    return sreader_skip(t->sr, n);
}

static int scan(tsrc *t, tar_member_fn cb, void *ctx, char *err, size_t errlen)
{
    unsigned char h[BLOCK];
    char *longname = NULL, *paxpath = NULL;
    uint64_t paxsize = 0;
    int have_paxsize = 0, members = 0, rc = 0;
    for (;;) {
        if (t_read(t, h, BLOCK) < 0 || all_zero(h) || !header_ok(h))
            break;
        uint64_t size = field_num(h + 124, 12);
        char type = (char)h[156];
        uint64_t padded = (size + BLOCK - 1) / BLOCK * BLOCK;
        if (type == 'L' || type == 'x') {
            if (size > (1u << 20)) {
                snprintf(err, errlen, "oversized tar extended header");
                rc = -1;
                break;
            }
            char *d = xmalloc((size_t)padded + 1);
            if (t_read(t, d, (size_t)padded) < 0) {
                free(d);
                break;
            }
            d[size] = 0;
            if (type == 'L') {
                free(longname);
                longname = xstrdup(d);
            } else {
                pax_parse(d, (size_t)size, &paxpath, &paxsize, &have_paxsize);
            }
            free(d);
            continue;
        }
        if (have_paxsize) {
            size = paxsize;
            padded = (size + BLOCK - 1) / BLOCK * BLOCK;
        }
        char *name;
        if (paxpath)
            name = xstrdup(paxpath);
        else if (longname)
            name = xstrdup(longname);
        else {
            char nm[101], pre[156];
            memcpy(nm, h, 100);
            nm[100] = 0;
            memcpy(pre, h + 345, 155);
            pre[155] = 0;
            name = !memcmp(h + 257, "ustar", 5) && pre[0] ? xasprintf("%s/%s", pre, nm) : xstrdup(nm);
        }
        free(longname);
        free(paxpath);
        longname = paxpath = NULL;
        have_paxsize = 0;
        members++;
        int r = 0;
        uint64_t used = 0;
        if (type == '0' || type == '\0' || type == '7') {
            sreader sr;
            if (t->rs) {
                rsrc_seq rq = {t->rs, t->pos, t->pos + size};
                sreader_init(&sr, rsrc_seq_read, &rq, size);
                r = cb(ctx, name, size, t->rs, t->pos, &sr);
            } else {
                sreader_init(&sr, sreader_read, t->sr, size);
                r = cb(ctx, name, size, NULL, 0, &sr);
                used = sr.consumed;
            }
            sreader_free(&sr);
        }
        free(name);
        if (r < 0) {
            rc = -1;
            break;
        }
        if (r > 0)
            break;
        if (t_skip(t, padded - used) < 0)
            break;
    }
    free(longname);
    free(paxpath);
    if (!rc && !members) {
        snprintf(err, errlen, "not a tar archive, or an empty one");
        return -1;
    }
    return rc;
}

int tar_scan_rsrc(rsrc *src, tar_member_fn cb, void *ctx, char *err, size_t errlen)
{
    tsrc t = {src, 0, NULL};
    return scan(&t, cb, ctx, err, errlen);
}

int tar_scan_stream(sreader *in, tar_member_fn cb, void *ctx, char *err, size_t errlen)
{
    tsrc t = {NULL, 0, in};
    return scan(&t, cb, ctx, err, errlen);
}

struct gzseq {
    seq_read_fn rd;
    void *ctx;
    z_stream z;
    unsigned char in[1u << 16];
    int done, failed;
};

gzseq *gzseq_open(seq_read_fn rd, void *ctx)
{
    gzseq *g = xcalloc(1, sizeof *g);
    g->rd = rd;
    g->ctx = ctx;
    if (inflateInit2(&g->z, 15 + 32) != Z_OK) {
        free(g);
        return NULL;
    }
    return g;
}

long gzseq_read(void *vg, void *buf, size_t len)
{
    gzseq *g = vg;
    if (g->failed)
        return -1;
    if (len > (1u << 30))
        len = 1u << 30;
    g->z.next_out = buf;
    g->z.avail_out = (uInt)len;
    while (g->z.avail_out == len && !g->done) {
        if (!g->z.avail_in) {
            long n = g->rd(g->ctx, g->in, sizeof g->in);
            if (n < 0) {
                g->failed = 1;
                return -1;
            }
            if (n == 0) {
                g->done = 1;
                break;
            }
            g->z.next_in = g->in;
            g->z.avail_in = (uInt)n;
        }
        int r = inflate(&g->z, Z_NO_FLUSH);
        if (r == Z_STREAM_END) {
            if (inflateReset(&g->z) != Z_OK) {
                g->failed = 1;
                return -1;
            }
        } else if (r != Z_OK && r != Z_BUF_ERROR) {
            g->failed = 1;
            return -1;
        }
    }
    return (long)(len - g->z.avail_out);
}

void gzseq_close(gzseq *g)
{
    if (!g)
        return;
    inflateEnd(&g->z);
    free(g);
}
