#include "formats/ota.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "core/util.h"

#ifdef HAVE_BROTLI
#include <brotli/decode.h>
#endif
#ifdef HAVE_LZMA
#include <lzma.h>
#endif
#ifdef HAVE_BZ2
#include <bzlib.h>
#endif
#ifdef HAVE_ZSTD
#include <zstd.h>
#endif

#define BLOCK 4096u

const char *ota_codecs(void)
{
    return ""
#ifdef HAVE_BROTLI
           " brotli"
#endif
#ifdef HAVE_LZMA
           " xz"
#endif
#ifdef HAVE_BZ2
           " bzip2"
#endif
#ifdef HAVE_ZSTD
           " zstd"
#endif
        ;
}

static int pwrite_all(int fd, const void *buf, size_t len, uint64_t off)
{
    const unsigned char *b = buf;
    while (len) {
        ssize_t n = pwrite(fd, b, len, (off_t)off);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        b += n;
        len -= (size_t)n;
        off += (uint64_t)n;
    }
    return 0;
}

typedef struct {
    uint64_t *v;
    size_t n;
} rangeset;

static int parse_ranges(const char *s, rangeset *r)
{
    char *end;
    unsigned long count = strtoul(s, &end, 10);
    if (end == s || count % 2 || count > 1u << 24)
        return -1;
    r->v = xcalloc(count ? count : 1, sizeof(uint64_t));
    r->n = count;
    for (unsigned long i = 0; i < count; i++) {
        if (*end != ',')
            return -1;
        s = end + 1;
        r->v[i] = strtoull(s, &end, 10);
        if (end == s)
            return -1;
    }
    for (size_t i = 0; i < r->n; i += 2)
        if (r->v[i] > r->v[i + 1])
            return -1;
    return 0;
}

typedef struct {
    seq_read_fn rd;
    void *ctx;
    int brotli;
#ifdef HAVE_BROTLI
    BrotliDecoderState *st;
    unsigned char in[1u << 16];
    const uint8_t *next_in;
    size_t avail_in;
    int in_eof;
#endif
} datsrc;

static int dat_read(datsrc *d, unsigned char *buf, size_t len)
{
    if (!d->brotli) {
        while (len) {
            long n = d->rd(d->ctx, buf, len);
            if (n <= 0)
                return -1;
            buf += n;
            len -= (size_t)n;
        }
        return 0;
    }
#ifdef HAVE_BROTLI
    size_t avail_out = len;
    uint8_t *next_out = buf;
    while (avail_out) {
        if (!d->avail_in && !d->in_eof) {
            long n = d->rd(d->ctx, d->in, sizeof d->in);
            if (n < 0)
                return -1;
            if (n == 0)
                d->in_eof = 1;
            d->next_in = d->in;
            d->avail_in = (size_t)n;
        }
        BrotliDecoderResult r =
            BrotliDecoderDecompressStream(d->st, &d->avail_in, &d->next_in, &avail_out, &next_out, NULL);
        if (r == BROTLI_DECODER_RESULT_ERROR)
            return -1;
        if (r == BROTLI_DECODER_RESULT_SUCCESS && avail_out)
            return -1;
        if (r == BROTLI_DECODER_RESULT_NEEDS_MORE_INPUT && d->in_eof && !d->avail_in)
            return -1;
    }
    return 0;
#else
    return -1;
#endif
}

rsrc *ota_from_dat(const char *list, size_t list_len, seq_read_fn rd, void *ctx, int brotli, const char *label,
                   char *err, size_t errlen)
{
#ifndef HAVE_BROTLI
    if (brotli) {
        snprintf(err, errlen, "this build has no brotli support (install libbrotli-dev and rebuild)");
        return NULL;
    }
#endif
    char *text = xstrndup(list, list_len);
    strvec lines = {0};
    for (char *save = NULL, *l = strtok_r(text, "\n", &save); l; l = strtok_r(NULL, "\n", &save)) {
        size_t ll = strlen(l);
        while (ll && (l[ll - 1] == '\r' || l[ll - 1] == ' '))
            l[--ll] = 0;
        strvec_push(&lines, l);
    }
    free(text);
    if (lines.n < 2) {
        strvec_free(&lines);
        snprintf(err, errlen, "transfer list is empty");
        return NULL;
    }
    int version = atoi(lines.v[0]);
    uint64_t total = strtoull(lines.v[1], NULL, 10);
    size_t first = version >= 2 ? 4 : 2;
    if (version < 1 || version > 4 || lines.n < first) {
        strvec_free(&lines);
        snprintf(err, errlen, "unsupported transfer list version %d", version);
        return NULL;
    }
    uint64_t max_block = total;
    for (size_t i = first; i < lines.n; i++) {
        const char *l = lines.v[i];
        const char *sp = strchr(l, ' ');
        size_t cl = sp ? (size_t)(sp - l) : strlen(l);
        if (!((cl == 3 && !strncmp(l, "new", 3)) || (cl == 4 && !strncmp(l, "zero", 4)) ||
              (cl == 5 && !strncmp(l, "erase", 5)))) {
            snprintf(err, errlen, "this is an incremental OTA (\"%.*s\" command); use the full ROM zip", (int)cl, l);
            strvec_free(&lines);
            return NULL;
        }
        rangeset r = {0};
        if (!sp || parse_ranges(sp + 1, &r) < 0) {
            free(r.v);
            snprintf(err, errlen, "corrupt transfer list line %zu", i + 1);
            strvec_free(&lines);
            return NULL;
        }
        for (size_t k = 1; k < r.n; k += 2)
            if (r.v[k] > max_block)
                max_block = r.v[k];
        free(r.v);
    }
    int fd = temp_fd();
    if (ftruncate(fd, (off_t)(max_block * BLOCK)) < 0)
        die("cannot size a temporary file: %s", strerror(errno));
    datsrc d;
    memset(&d, 0, sizeof d);
    d.rd = rd;
    d.ctx = ctx;
    d.brotli = brotli;
#ifdef HAVE_BROTLI
    if (brotli)
        d.st = BrotliDecoderCreateInstance(NULL, NULL, NULL);
#endif
    unsigned char *buf = xmalloc(256 * BLOCK);
    int ok = 1;
    uint64_t written = 0;
    for (size_t i = first; i < lines.n && ok; i++) {
        if (strncmp(lines.v[i], "new ", 4))
            continue;
        rangeset r = {0};
        parse_ranges(lines.v[i] + 4, &r);
        for (size_t k = 0; k < r.n && ok; k += 2) {
            for (uint64_t b = r.v[k]; b < r.v[k + 1] && ok;) {
                uint64_t nb = r.v[k + 1] - b > 256 ? 256 : r.v[k + 1] - b;
                if (dat_read(&d, buf, (size_t)(nb * BLOCK)) < 0) {
                    snprintf(err, errlen, "%s: data ends early or is corrupt", label);
                    ok = 0;
                } else if (pwrite_all(fd, buf, (size_t)(nb * BLOCK), b * BLOCK) < 0) {
                    die("writing a temporary file failed: %s", strerror(errno));
                }
                b += nb;
                written += nb;
            }
        }
        free(r.v);
    }
    free(buf);
#ifdef HAVE_BROTLI
    if (d.st)
        BrotliDecoderDestroyInstance(d.st);
#endif
    strvec_free(&lines);
    if (!ok) {
        close(fd);
        return NULL;
    }
    debug("%s: %llu blocks written", label, (unsigned long long)written);
    return rsrc_open_fd(fd, label);
}

typedef struct {
    uint64_t start, num;
} extent;

typedef struct {
    int type;
    uint64_t data_off, data_len;
    extent *dst;
    size_t ndst;
} op_t;

typedef struct {
    char *name;
    uint64_t size;
    op_t *ops;
    size_t nops;
} part_t;

struct payload {
    rsrc *src;
    uint64_t data_start;
    uint32_t block;
    part_t *parts;
    size_t nparts;
};

typedef struct {
    const unsigned char *p, *end;
} pb;

static int pb_varint(pb *b, uint64_t *v)
{
    uint64_t r = 0;
    for (int s = 0; s < 64 && b->p < b->end; s += 7) {
        unsigned char c = *b->p++;
        r |= (uint64_t)(c & 0x7f) << s;
        if (!(c & 0x80)) {
            *v = r;
            return 0;
        }
    }
    return -1;
}

static int pb_field(pb *b, uint32_t *field, int *wt, uint64_t *v, pb *sub)
{
    uint64_t key;
    if (pb_varint(b, &key) < 0)
        return -1;
    *field = (uint32_t)(key >> 3);
    *wt = (int)(key & 7);
    switch (*wt) {
    case 0:
        return pb_varint(b, v);
    case 1:
        if (b->end - b->p < 8)
            return -1;
        *v = le64(b->p);
        b->p += 8;
        return 0;
    case 2: {
        uint64_t len;
        if (pb_varint(b, &len) < 0 || len > (uint64_t)(b->end - b->p))
            return -1;
        sub->p = b->p;
        sub->end = b->p + len;
        b->p += len;
        return 0;
    }
    case 5:
        if (b->end - b->p < 4)
            return -1;
        *v = le32(b->p);
        b->p += 4;
        return 0;
    default:
        return -1;
    }
}

static int parse_op(pb b, op_t *op)
{
    memset(op, 0, sizeof *op);
    while (b.p < b.end) {
        uint32_t f;
        int wt;
        uint64_t v = 0;
        pb sub = {0};
        if (pb_field(&b, &f, &wt, &v, &sub) < 0)
            return -1;
        if (f == 1 && wt == 0)
            op->type = (int)v;
        else if (f == 2 && wt == 0)
            op->data_off = v;
        else if (f == 3 && wt == 0)
            op->data_len = v;
        else if (f == 6 && wt == 2) {
            extent e = {0, 0};
            while (sub.p < sub.end) {
                uint32_t ef;
                int ewt;
                uint64_t ev = 0;
                pb esub;
                if (pb_field(&sub, &ef, &ewt, &ev, &esub) < 0)
                    return -1;
                if (ef == 1 && ewt == 0)
                    e.start = ev;
                else if (ef == 2 && ewt == 0)
                    e.num = ev;
            }
            op->dst = xrealloc(op->dst, (op->ndst + 1) * sizeof(extent));
            op->dst[op->ndst++] = e;
        }
    }
    return 0;
}

static int parse_part(pb b, part_t *pt)
{
    memset(pt, 0, sizeof *pt);
    size_t cap = 0;
    while (b.p < b.end) {
        uint32_t f;
        int wt;
        uint64_t v = 0;
        pb sub = {0};
        if (pb_field(&b, &f, &wt, &v, &sub) < 0)
            return -1;
        if (f == 1 && wt == 2) {
            free(pt->name);
            pt->name = xstrndup((const char *)sub.p, (size_t)(sub.end - sub.p));
        } else if (f == 7 && wt == 2) {
            while (sub.p < sub.end) {
                uint32_t pf;
                int pwt;
                uint64_t pv = 0;
                pb psub;
                if (pb_field(&sub, &pf, &pwt, &pv, &psub) < 0)
                    return -1;
                if (pf == 1 && pwt == 0)
                    pt->size = pv;
            }
        } else if (f == 8 && wt == 2) {
            if (pt->nops == cap) {
                cap = cap ? cap * 2 : 64;
                pt->ops = xrealloc(pt->ops, cap * sizeof(op_t));
            }
            if (parse_op(sub, &pt->ops[pt->nops]) < 0)
                return -1;
            pt->nops++;
        }
    }
    return pt->name ? 0 : -1;
}

payload *payload_open(rsrc *src, char *err, size_t errlen)
{
    unsigned char h[24];
    if (rsrc_read(src, h, 24, 0) < 0 || memcmp(h, "CrAU", 4)) {
        snprintf(err, errlen, "not an OTA payload");
        return NULL;
    }
    uint64_t version = ((uint64_t)h[4] << 56) | ((uint64_t)h[5] << 48) | ((uint64_t)h[6] << 40) |
                       ((uint64_t)h[7] << 32) | ((uint64_t)h[8] << 24) | ((uint64_t)h[9] << 16) |
                       ((uint64_t)h[10] << 8) | h[11];
    uint64_t msize = 0;
    for (int i = 12; i < 20; i++)
        msize = (msize << 8) | h[i];
    uint32_t sigsize = ((uint32_t)h[20] << 24) | ((uint32_t)h[21] << 16) | ((uint32_t)h[22] << 8) | h[23];
    if (version != 2) {
        snprintf(err, errlen, "unsupported payload version %llu", (unsigned long long)version);
        return NULL;
    }
    if (msize > (512u << 20) || 24 + msize > src->size) {
        snprintf(err, errlen, "corrupt payload manifest");
        return NULL;
    }
    unsigned char *m = xmalloc((size_t)msize);
    if (rsrc_read(src, m, (size_t)msize, 24) < 0) {
        free(m);
        snprintf(err, errlen, "cannot read payload manifest");
        return NULL;
    }
    payload *p = xcalloc(1, sizeof *p);
    p->src = src;
    p->block = BLOCK;
    p->data_start = 24 + msize + sigsize;
    pb b = {m, m + msize};
    while (b.p < b.end) {
        uint32_t f;
        int wt;
        uint64_t v = 0;
        pb sub = {0};
        if (pb_field(&b, &f, &wt, &v, &sub) < 0) {
            snprintf(err, errlen, "corrupt payload manifest");
            free(m);
            payload_close(p);
            return NULL;
        }
        if (f == 3 && wt == 0)
            p->block = (uint32_t)v;
        else if (f == 13 && wt == 2) {
            p->parts = xrealloc(p->parts, (p->nparts + 1) * sizeof(part_t));
            if (parse_part(sub, &p->parts[p->nparts]) < 0) {
                snprintf(err, errlen, "corrupt partition entry in payload manifest");
                free(m);
                p->nparts++;
                payload_close(p);
                return NULL;
            }
            p->nparts++;
        }
    }
    free(m);
    if (!p->block || p->block > (1u << 20))
        p->block = BLOCK;
    return p;
}

size_t payload_count(const payload *p)
{
    return p->nparts;
}

const char *payload_name(const payload *p, size_t i)
{
    return p->parts[i].name;
}

uint64_t payload_size(const payload *p, size_t i)
{
    return p->parts[i].size;
}

static const char *op_name(int t)
{
    switch (t) {
    case 0: return "REPLACE";
    case 1: return "REPLACE_BZ";
    case 2: return "MOVE";
    case 3: return "BSDIFF";
    case 4: return "SOURCE_COPY";
    case 5: return "SOURCE_BSDIFF";
    case 6: return "ZERO";
    case 7: return "DISCARD";
    case 8: return "REPLACE_XZ";
    case 9: return "PUFFDIFF";
    case 10: return "BROTLI_BSDIFF";
    case 11: return "ZUCCHINI";
    case 14: return "REPLACE_ZSTD";
    default: return "LZ4DIFF";
    }
}

static int decode_op(int type, const unsigned char *in, size_t in_len, unsigned char *out, size_t out_len)
{
    switch (type) {
    case 0:
        if (in_len > out_len)
            return -1;
        memcpy(out, in, in_len);
        memset(out + in_len, 0, out_len - in_len);
        return 0;
#ifdef HAVE_BZ2
    case 1: {
        unsigned int dl = (unsigned int)out_len;
        int r = BZ2_bzBuffToBuffDecompress((char *)out, &dl, (char *)in, (unsigned int)in_len, 0, 0);
        if (r != BZ_OK && r != BZ_OUTBUFF_FULL)
            return -1;
        if (dl < out_len)
            memset(out + dl, 0, out_len - dl);
        return 0;
    }
#endif
#ifdef HAVE_LZMA
    case 8: {
        lzma_stream s = LZMA_STREAM_INIT;
        if (lzma_stream_decoder(&s, UINT64_MAX, LZMA_CONCATENATED) != LZMA_OK)
            return -1;
        s.next_in = in;
        s.avail_in = in_len;
        s.next_out = out;
        s.avail_out = out_len;
        lzma_ret r = lzma_code(&s, LZMA_FINISH);
        size_t got = out_len - s.avail_out;
        lzma_end(&s);
        if (r != LZMA_STREAM_END && !(r == LZMA_OK && got == out_len) && r != LZMA_BUF_ERROR)
            return -1;
        if (got < out_len)
            memset(out + got, 0, out_len - got);
        return 0;
    }
#endif
#ifdef HAVE_ZSTD
    case 14: {
        size_t r = ZSTD_decompress(out, out_len, in, in_len);
        if (ZSTD_isError(r))
            return -1;
        if (r < out_len)
            memset(out + r, 0, out_len - r);
        return 0;
    }
#endif
    default:
        return -2;
    }
}

rsrc *payload_extract(payload *p, size_t idx, char *err, size_t errlen)
{
    part_t *pt = &p->parts[idx];
    uint64_t size = pt->size;
    for (size_t i = 0; i < pt->nops; i++) {
        op_t *op = &pt->ops[i];
        if (op->type != 0 && op->type != 1 && op->type != 6 && op->type != 7 && op->type != 8 && op->type != 14) {
            snprintf(err, errlen, "%s uses %s: this is an incremental OTA, use the full ROM zip", pt->name,
                     op_name(op->type));
            return NULL;
        }
        for (size_t k = 0; k < op->ndst; k++) {
            uint64_t end = (op->dst[k].start + op->dst[k].num) * p->block;
            if (end > size)
                size = end;
        }
    }
    int fd = temp_fd();
    if (ftruncate(fd, (off_t)size) < 0)
        die("cannot size a temporary file: %s", strerror(errno));
    note("  extracting  %s from payload.bin (%llu MiB)", pt->name, (unsigned long long)(size >> 20));
    for (size_t i = 0; i < pt->nops; i++) {
        op_t *op = &pt->ops[i];
        if (op->type == 6 || op->type == 7)
            continue;
        uint64_t out_len = 0;
        for (size_t k = 0; k < op->ndst; k++)
            out_len += op->dst[k].num * p->block;
        if (op->data_len > (1u << 30) || out_len > (1u << 30)) {
            snprintf(err, errlen, "%s: operation too large", pt->name);
            close(fd);
            return NULL;
        }
        unsigned char *in = xmalloc((size_t)op->data_len + 1);
        unsigned char *out = xmalloc((size_t)out_len + 1);
        if (rsrc_read(p->src, in, (size_t)op->data_len, p->data_start + op->data_off) < 0) {
            free(in);
            free(out);
            close(fd);
            snprintf(err, errlen, "%s: payload data is truncated", pt->name);
            return NULL;
        }
        int r = decode_op(op->type, in, (size_t)op->data_len, out, (size_t)out_len);
        free(in);
        if (r < 0) {
            free(out);
            close(fd);
            if (r == -2)
                snprintf(err, errlen, "%s: %s data needs a decompressor this build lacks (have:%s)", pt->name,
                         op_name(op->type), ota_codecs());
            else
                snprintf(err, errlen, "%s: corrupt %s data", pt->name, op_name(op->type));
            return NULL;
        }
        uint64_t pos = 0;
        for (size_t k = 0; k < op->ndst; k++) {
            uint64_t len = op->dst[k].num * p->block;
            if (pwrite_all(fd, out + pos, (size_t)len, op->dst[k].start * p->block) < 0)
                die("writing a temporary file failed: %s", strerror(errno));
            pos += len;
        }
        free(out);
    }
    char *label = xasprintf("payload.bin:%s", pt->name);
    rsrc *r = rsrc_open_fd(fd, label);
    free(label);
    return r;
}

void payload_close(payload *p)
{
    if (!p)
        return;
    for (size_t i = 0; i < p->nparts; i++) {
        free(p->parts[i].name);
        for (size_t k = 0; k < p->parts[i].nops; k++)
            free(p->parts[i].ops[k].dst);
        free(p->parts[i].ops);
    }
    free(p->parts);
    free(p);
}
