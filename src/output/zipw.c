#include "output/zipw.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <zlib.h>

#include "core/util.h"

#define Z64_LIMIT 0xFFFFFFFFULL
#define Z64_LOCAL_THRESHOLD 0xFF000000ULL

typedef struct {
    char *name;
    uint16_t method, flags, version;
    uint32_t crc;
    uint64_t csize, usize, off;
    uint32_t ext_attr;
    uint16_t dtime, ddate;
} cent;

struct zipw {
    FILE *fp;
    int level;
    uint64_t pos;
    cent *c;
    size_t n, cap;
    int failed;

    int in_file;
    int deflating;
    int local_z64;
    uint64_t declared;
    uint64_t written;
    uint32_t crc;
    uint64_t csize;
    z_stream zs;
    unsigned char out[1u << 16];
};

static int put(zipw *w, const void *p, size_t n)
{
    if (w->failed)
        return -1;
    if (n && fwrite(p, 1, n, w->fp) != n) {
        w->failed = 1;
        return -1;
    }
    w->pos += n;
    return 0;
}

static void p16(unsigned char *b, uint16_t v)
{
    b[0] = (unsigned char)v;
    b[1] = (unsigned char)(v >> 8);
}

static void p64(unsigned char *b, uint64_t v)
{
    put_le32(b, (uint32_t)v);
    put_le32(b + 4, (uint32_t)(v >> 32));
}

static void dos_time(int64_t mtime, uint16_t *t, uint16_t *d)
{
    time_t tt = mtime > 315532800 ? (time_t)mtime : 1199145600;
    struct tm tm;
    gmtime_r(&tt, &tm);
    if (tm.tm_year < 80)
        tm.tm_year = 80;
    if (tm.tm_year > 207)
        tm.tm_year = 207;
    *t = (uint16_t)((tm.tm_hour << 11) | (tm.tm_min << 5) | (tm.tm_sec / 2));
    *d = (uint16_t)(((tm.tm_year - 80) << 9) | ((tm.tm_mon + 1) << 5) | tm.tm_mday);
}

zipw *zipw_open(const char *path, int level)
{
    zipw *w = xcalloc(1, sizeof *w);
    w->fp = fopen(path, "w+b");
    if (!w->fp) {
        free(w);
        return NULL;
    }
    setvbuf(w->fp, NULL, _IOFBF, 1u << 20);
    w->level = level;
    return w;
}

static cent *add_cent(zipw *w, const char *name)
{
    if (w->n == w->cap) {
        w->cap = w->cap ? w->cap * 2 : 1024;
        w->c = xrealloc(w->c, w->cap * sizeof(cent));
    }
    cent *c = &w->c[w->n++];
    memset(c, 0, sizeof *c);
    c->name = xstrdup(name);
    c->off = w->pos;
    c->flags = 0x0800;
    c->version = 20;
    return c;
}

static int local_header(zipw *w, cent *c, int z64)
{
    size_t nl = strlen(c->name);
    unsigned char h[30];
    memset(h, 0, sizeof h);
    put_le32(h, 0x04034b50U);
    p16(h + 4, z64 ? 45 : c->version);
    p16(h + 6, c->flags);
    p16(h + 8, c->method);
    p16(h + 10, c->dtime);
    p16(h + 12, c->ddate);
    put_le32(h + 14, c->crc);
    put_le32(h + 18, z64 ? 0xFFFFFFFFU : (uint32_t)c->csize);
    put_le32(h + 22, z64 ? 0xFFFFFFFFU : (uint32_t)c->usize);
    p16(h + 26, (uint16_t)nl);
    p16(h + 28, z64 ? 20 : 0);
    if (put(w, h, 30) < 0 || put(w, c->name, nl) < 0)
        return -1;
    if (z64) {
        unsigned char x[20];
        p16(x, 1);
        p16(x + 2, 16);
        p64(x + 4, c->usize);
        p64(x + 12, c->csize);
        return put(w, x, 20);
    }
    return 0;
}

static int small_entry(zipw *w, const char *name, uint32_t attr, const void *data, size_t len, int64_t mtime)
{
    cent *c = add_cent(w, name);
    c->method = 0;
    c->ext_attr = attr;
    c->crc = len ? (uint32_t)crc32(0, data, (uInt)len) : 0;
    c->csize = c->usize = len;
    dos_time(mtime, &c->dtime, &c->ddate);
    if (local_header(w, c, 0) < 0)
        return -1;
    return put(w, data, len);
}

int zipw_dir(zipw *w, const char *name, uint32_t mode, int64_t mtime)
{
    char *n = xasprintf("%s/", name);
    int r = small_entry(w, n, ((0040000u | (mode & 07777)) << 16) | 0x10, NULL, 0, mtime);
    free(n);
    return r;
}

int zipw_symlink(zipw *w, const char *name, const char *target, int64_t mtime)
{
    return small_entry(w, name, (0120777u << 16), target, strlen(target), mtime);
}

int zipw_file_begin(zipw *w, const char *name, uint64_t size, uint32_t mode, int64_t mtime, int compress)
{
    cent *c = add_cent(w, name);
    c->ext_attr = (0100000u | (mode & 07777)) << 16;
    dos_time(mtime, &c->dtime, &c->ddate);
    w->deflating = compress && w->level > 0 && size > 64;
    c->method = w->deflating ? 8 : 0;
    w->local_z64 = size >= Z64_LOCAL_THRESHOLD;
    if (w->local_z64)
        c->version = 45;
    c->usize = size;
    c->csize = w->deflating ? 0 : size;
    if (local_header(w, c, w->local_z64) < 0)
        return -1;
    if (w->deflating) {
        memset(&w->zs, 0, sizeof w->zs);
        if (deflateInit2(&w->zs, w->level, Z_DEFLATED, -15, 8, Z_DEFAULT_STRATEGY) != Z_OK)
            return -1;
    }
    w->in_file = 1;
    w->declared = size;
    w->written = 0;
    w->crc = 0;
    w->csize = 0;
    return 0;
}

static int drain(zipw *w, int flush)
{
    int r;
    do {
        w->zs.next_out = w->out;
        w->zs.avail_out = sizeof w->out;
        r = deflate(&w->zs, flush);
        if (r == Z_STREAM_ERROR)
            return -1;
        size_t got = sizeof w->out - w->zs.avail_out;
        w->csize += got;
        if (put(w, w->out, got) < 0)
            return -1;
    } while (w->zs.avail_out == 0 || (flush == Z_FINISH && r != Z_STREAM_END));
    return 0;
}

int zipw_write(zipw *w, const void *data, size_t len)
{
    if (!w->in_file || w->written + len > w->declared) {
        w->failed = 1;
        return -1;
    }
    const unsigned char *p = data;
    size_t left = len;
    while (left) {
        uInt chunk = left > (1u << 30) ? (1u << 30) : (uInt)left;
        w->crc = (uint32_t)crc32(w->crc, p, chunk);
        if (w->deflating) {
            w->zs.next_in = (unsigned char *)p;
            w->zs.avail_in = chunk;
            if (drain(w, Z_NO_FLUSH) < 0)
                return -1;
        } else {
            if (put(w, p, chunk) < 0)
                return -1;
            w->csize += chunk;
        }
        p += chunk;
        left -= chunk;
    }
    w->written += len;
    return 0;
}

int zipw_file_end(zipw *w)
{
    if (!w->in_file || w->written != w->declared) {
        w->failed = 1;
        return -1;
    }
    w->in_file = 0;
    if (w->deflating) {
        w->zs.next_in = NULL;
        w->zs.avail_in = 0;
        if (drain(w, Z_FINISH) < 0)
            return -1;
        deflateEnd(&w->zs);
    }
    cent *c = &w->c[w->n - 1];
    c->crc = w->crc;
    c->csize = w->csize;
    if (!w->local_z64 && c->csize >= Z64_LIMIT) {
        warn("%s: compressed size exceeds 4 GiB", c->name);
        w->failed = 1;
        return -1;
    }
    if (fflush(w->fp) != 0)
        return -1;
    off_t back = (off_t)(c->off + 14);
    if (fseeko(w->fp, back, SEEK_SET) < 0)
        return -1;
    unsigned char f[12];
    put_le32(f, c->crc);
    put_le32(f + 4, w->local_z64 ? 0xFFFFFFFFU : (uint32_t)c->csize);
    put_le32(f + 8, w->local_z64 ? 0xFFFFFFFFU : (uint32_t)c->usize);
    if (fwrite(f, 1, 12, w->fp) != 12)
        return -1;
    if (w->local_z64) {
        if (fseeko(w->fp, (off_t)(c->off + 30 + strlen(c->name) + 4), SEEK_SET) < 0)
            return -1;
        unsigned char x[16];
        p64(x, c->usize);
        p64(x + 8, c->csize);
        if (fwrite(x, 1, 16, w->fp) != 16)
            return -1;
    }
    if (fseeko(w->fp, (off_t)w->pos, SEEK_SET) < 0)
        return -1;
    return 0;
}

int zipw_raw_copy(zipw *w, zipr *src, zip_entry *e, const char *name)
{
    if (zipr_data_offset(src, e) < 0)
        return -1;
    cent *c = add_cent(w, name ? name : e->name);
    c->method = e->method;
    c->flags = (uint16_t)((e->flags & 0x0800) | 0x0800);
    c->crc = e->crc;
    c->csize = e->csize;
    c->usize = e->usize;
    c->ext_attr = (e->made_by >> 8) == 3 ? e->ext_attr : (0100644u << 16);
    c->dtime = e->dos_time;
    c->ddate = e->dos_date;
    int z64 = e->csize >= Z64_LIMIT || e->usize >= Z64_LIMIT;
    if (z64)
        c->version = 45;
    if (local_header(w, c, z64) < 0)
        return -1;
    unsigned char *buf = xmalloc(1u << 20);
    uint64_t off = 0;
    while (off < e->csize) {
        size_t n = e->csize - off > (1u << 20) ? (1u << 20) : (size_t)(e->csize - off);
        if (rsrc_read(src->src, buf, n, e->data_off + off) < 0 || put(w, buf, n) < 0) {
            free(buf);
            return -1;
        }
        off += n;
    }
    free(buf);
    return 0;
}

int zipw_close(zipw *w)
{
    int r = 0;
    uint64_t cd_start = w->pos;
    for (size_t i = 0; i < w->n && r == 0; i++) {
        cent *c = &w->c[i];
        int zu = c->usize >= Z64_LIMIT, zc = c->csize >= Z64_LIMIT, zo = c->off >= Z64_LIMIT;
        size_t nl = strlen(c->name);
        unsigned char h[46];
        unsigned char x[28];
        size_t xl = 0;
        if (zu || zc || zo) {
            p16(x, 1);
            xl = 4;
            if (zu) {
                p64(x + xl, c->usize);
                xl += 8;
            }
            if (zc) {
                p64(x + xl, c->csize);
                xl += 8;
            }
            if (zo) {
                p64(x + xl, c->off);
                xl += 8;
            }
            p16(x + 2, (uint16_t)(xl - 4));
        }
        memset(h, 0, sizeof h);
        put_le32(h, 0x02014b50U);
        p16(h + 4, (3 << 8) | 63);
        p16(h + 6, xl ? 45 : c->version);
        p16(h + 8, c->flags);
        p16(h + 10, c->method);
        p16(h + 12, c->dtime);
        p16(h + 14, c->ddate);
        put_le32(h + 16, c->crc);
        put_le32(h + 20, zc ? 0xFFFFFFFFU : (uint32_t)c->csize);
        put_le32(h + 24, zu ? 0xFFFFFFFFU : (uint32_t)c->usize);
        p16(h + 28, (uint16_t)nl);
        p16(h + 30, (uint16_t)xl);
        put_le32(h + 38, c->ext_attr);
        put_le32(h + 42, zo ? 0xFFFFFFFFU : (uint32_t)c->off);
        if (put(w, h, 46) < 0 || put(w, c->name, nl) < 0 || put(w, x, xl) < 0)
            r = -1;
    }
    uint64_t cd_size = w->pos - cd_start;
    int z64 = w->n >= 0xFFFF || cd_start >= Z64_LIMIT || cd_size >= Z64_LIMIT;
    if (r == 0 && z64) {
        uint64_t z64_off = w->pos;
        unsigned char e[56];
        memset(e, 0, sizeof e);
        put_le32(e, 0x06064b50U);
        p64(e + 4, 44);
        p16(e + 12, (3 << 8) | 63);
        p16(e + 14, 45);
        p64(e + 24, w->n);
        p64(e + 32, w->n);
        p64(e + 40, cd_size);
        p64(e + 48, cd_start);
        unsigned char l[20];
        memset(l, 0, sizeof l);
        put_le32(l, 0x07064b50U);
        p64(l + 8, z64_off);
        put_le32(l + 16, 1);
        if (put(w, e, 56) < 0 || put(w, l, 20) < 0)
            r = -1;
    }
    if (r == 0) {
        unsigned char e[22];
        memset(e, 0, sizeof e);
        put_le32(e, 0x06054b50U);
        p16(e + 8, w->n >= 0xFFFF ? 0xFFFF : (uint16_t)w->n);
        p16(e + 10, w->n >= 0xFFFF ? 0xFFFF : (uint16_t)w->n);
        put_le32(e + 12, cd_size >= Z64_LIMIT ? 0xFFFFFFFFU : (uint32_t)cd_size);
        put_le32(e + 16, cd_start >= Z64_LIMIT ? 0xFFFFFFFFU : (uint32_t)cd_start);
        if (put(w, e, 22) < 0)
            r = -1;
    }
    if (fclose(w->fp) != 0 || w->failed)
        r = -1;
    for (size_t i = 0; i < w->n; i++)
        free(w->c[i].name);
    free(w->c);
    free(w);
    return r;
}

uint64_t zipw_bytes(const zipw *w)
{
    return w->pos;
}
