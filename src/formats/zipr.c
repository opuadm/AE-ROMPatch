#include "formats/zipr.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <zlib.h>

typedef struct {
    rsrc *base;
    uint64_t off;
} slice_priv;

static int slice_pread(rsrc *s, void *buf, size_t len, uint64_t off)
{
    slice_priv *p = s->priv;
    if (off > s->size || len > s->size - off) {
        memset(buf, 0, len);
        return -1;
    }
    return rsrc_read(p->base, buf, len, p->off + off);
}

static void slice_close(rsrc *s)
{
    free(s->priv);
}

rsrc *rsrc_open_slice(rsrc *base, uint64_t off, uint64_t size, const char *name)
{
    rsrc *s = xcalloc(1, sizeof *s);
    slice_priv *p = xcalloc(1, sizeof *p);
    p->base = base;
    p->off = off;
    s->priv = p;
    s->size = size;
    s->name = xstrdup(name);
    s->pread = slice_pread;
    s->close = slice_close;
    return s;
}

int zipr_probe(const char *path)
{
    unsigned char h[4];
    FILE *f = fopen(path, "rb");
    if (!f)
        return 0;
    size_t n = fread(h, 1, 4, f);
    fclose(f);
    return n == 4 && !memcmp(h, "PK\3\4", 4);
}

static int parse_cd(zipr *z, char *err, size_t errlen)
{
    uint64_t size = z->src->size;
    if (size < 22) {
        snprintf(err, errlen, "too small to be a zip");
        return -1;
    }
    size_t tail = size < 65557 ? (size_t)size : 65557;
    unsigned char *t = xmalloc(tail);
    if (rsrc_read(z->src, t, tail, size - tail) < 0) {
        free(t);
        snprintf(err, errlen, "read error");
        return -1;
    }
    long eocd = -1;
    for (long i = (long)tail - 22; i >= 0; i--) {
        if (le32(t + i) == 0x06054b50U) {
            eocd = i;
            break;
        }
    }
    if (eocd < 0) {
        free(t);
        snprintf(err, errlen, "no zip central directory (truncated download?)");
        return -1;
    }
    uint64_t eocd_pos = size - tail + (uint64_t)eocd;
    uint64_t entries = le16(t + eocd + 10);
    uint64_t cd_size = le32(t + eocd + 12);
    uint64_t cd_off = le32(t + eocd + 16);
    int zip64 = 0;
    if (eocd >= 20 && le32(t + eocd - 20) == 0x07064b50U) {
        uint64_t z64 = le64(t + eocd - 20 + 8);
        unsigned char r[56];
        if (rsrc_read(z->src, r, sizeof r, z64) == 0 && le32(r) == 0x06064b50U) {
            entries = le64(r + 32);
            cd_size = le64(r + 40);
            cd_off = le64(r + 48);
            zip64 = 1;
        }
    }
    free(t);
    uint64_t shift = 0;
    if (!zip64 && cd_off + cd_size < eocd_pos)
        shift = eocd_pos - (cd_off + cd_size);
    if (cd_off + shift + cd_size > size || cd_size > (1ULL << 31) || entries > 10000000) {
        snprintf(err, errlen, "corrupt zip central directory");
        return -1;
    }
    unsigned char *cd = xmalloc((size_t)cd_size + 1);
    if (rsrc_read(z->src, cd, (size_t)cd_size, cd_off + shift) < 0) {
        free(cd);
        snprintf(err, errlen, "cannot read zip central directory");
        return -1;
    }
    z->e = xcalloc(entries ? (size_t)entries : 1, sizeof(zip_entry));
    size_t p = 0;
    for (uint64_t i = 0; i < entries; i++) {
        if (p + 46 > cd_size || le32(cd + p) != 0x02014b50U) {
            free(cd);
            snprintf(err, errlen, "corrupt zip central directory entry %llu", (unsigned long long)i);
            return -1;
        }
        zip_entry *e = &z->e[z->n];
        e->made_by = le16(cd + p + 4);
        e->flags = le16(cd + p + 8);
        e->method = le16(cd + p + 10);
        e->dos_time = le16(cd + p + 12);
        e->dos_date = le16(cd + p + 14);
        e->crc = le32(cd + p + 16);
        e->csize = le32(cd + p + 20);
        e->usize = le32(cd + p + 24);
        uint16_t nlen = le16(cd + p + 28), elen = le16(cd + p + 30), clen = le16(cd + p + 32);
        e->ext_attr = le32(cd + p + 38);
        e->lho = le32(cd + p + 42);
        if (p + 46 + nlen + elen + clen > cd_size) {
            free(cd);
            snprintf(err, errlen, "corrupt zip central directory");
            return -1;
        }
        e->name = xstrndup((const char *)cd + p + 46, nlen);
        for (char *c = e->name; *c; c++)
            if (*c == '\\')
                *c = '/';
        const unsigned char *x = cd + p + 46 + nlen;
        size_t xp = 0;
        while (xp + 4 <= elen) {
            uint16_t id = le16(x + xp), sz = le16(x + xp + 2);
            if (xp + 4 + sz > elen)
                break;
            if (id == 0x0001) {
                size_t q = xp + 4, end = xp + 4 + sz;
                if (e->usize == 0xFFFFFFFFU && q + 8 <= end) {
                    e->usize = le64(x + q);
                    q += 8;
                }
                if (e->csize == 0xFFFFFFFFU && q + 8 <= end) {
                    e->csize = le64(x + q);
                    q += 8;
                }
                if (e->lho == 0xFFFFFFFFU && q + 8 <= end)
                    e->lho = le64(x + q);
            }
            xp += 4 + sz;
        }
        e->lho += shift;
        e->data_off = UINT64_MAX;
        z->n++;
        p += 46 + nlen + elen + clen;
    }
    free(cd);
    return 0;
}

zipr *zipr_open_rsrc(rsrc *src, const char *label, char *err, size_t errlen)
{
    zipr *z = xcalloc(1, sizeof *z);
    z->src = src;
    z->path = xstrdup(label);
    if (parse_cd(z, err, errlen) < 0) {
        z->src = NULL;
        zipr_close(z);
        return NULL;
    }
    return z;
}

zipr *zipr_open(const char *path, char *err, size_t errlen)
{
    rsrc *src = rsrc_open_file(path);
    if (!src) {
        snprintf(err, errlen, "%s", strerror(errno));
        return NULL;
    }
    zipr *z = zipr_open_rsrc(src, path, err, errlen);
    if (!z)
        rsrc_close(src);
    return z;
}

void zipr_close(zipr *z)
{
    if (!z)
        return;
    for (size_t i = 0; i < z->n; i++)
        free(z->e[i].name);
    free(z->e);
    rsrc_close(z->src);
    free(z->path);
    free(z);
}

int zip_entry_is_dir(const zip_entry *e)
{
    size_t l = strlen(e->name);
    return (l && e->name[l - 1] == '/') || ((e->made_by >> 8) == 3 && ((e->ext_attr >> 16) & 0xF000) == 0x4000);
}

int zip_entry_is_symlink(const zip_entry *e)
{
    return (e->made_by >> 8) == 3 && ((e->ext_attr >> 16) & 0xF000) == 0xA000;
}

uint32_t zip_entry_mode(const zip_entry *e)
{
    if ((e->made_by >> 8) == 3)
        return (e->ext_attr >> 16) & 07777;
    return 0;
}

int zipr_data_offset(zipr *z, zip_entry *e)
{
    if (e->data_off != UINT64_MAX)
        return 0;
    unsigned char h[30];
    if (rsrc_read(z->src, h, 30, e->lho) < 0 || le32(h) != 0x04034b50U)
        return -1;
    e->data_off = e->lho + 30 + le16(h + 26) + le16(h + 28);
    if (e->data_off + e->csize > z->src->size)
        return -1;
    return 0;
}

static int check_supported(zipr *z, zip_entry *e)
{
    if (e->flags & 1) {
        warn("%s: %s is encrypted", z->path, e->name);
        return -1;
    }
    if (e->method != 0 && e->method != 8) {
        warn("%s: %s uses zip compression method %u, which is not supported", z->path, e->name, e->method);
        return -1;
    }
    if (zipr_data_offset(z, e) < 0) {
        warn("%s: %s: corrupt local header", z->path, e->name);
        return -1;
    }
    return 0;
}

struct zstream {
    zipr *z;
    zip_entry *e;
    uint64_t in_pos;
    uint64_t out_pos;
    z_stream zs;
    int inflating;
    int done;
    unsigned char in[65536];
};

zstream *zstream_open(zipr *z, zip_entry *e)
{
    if (check_supported(z, e) < 0)
        return NULL;
    zstream *s = xcalloc(1, sizeof *s);
    s->z = z;
    s->e = e;
    if (e->method == 8) {
        if (inflateInit2(&s->zs, -15) != Z_OK) {
            free(s);
            return NULL;
        }
        s->inflating = 1;
    }
    return s;
}

long zstream_read(zstream *s, void *buf, size_t len)
{
    if (!len || s->done)
        return 0;
    if (!s->inflating) {
        uint64_t left = s->e->usize - s->out_pos;
        size_t n = left < len ? (size_t)left : len;
        if (!n) {
            s->done = 1;
            return 0;
        }
        if (rsrc_read(s->z->src, buf, n, s->e->data_off + s->out_pos) < 0)
            return -1;
        s->out_pos += n;
        return (long)n;
    }
    s->zs.next_out = buf;
    s->zs.avail_out = (uInt)(len > (1u << 30) ? (1u << 30) : len);
    uInt want = s->zs.avail_out;
    while (s->zs.avail_out) {
        if (!s->zs.avail_in) {
            uint64_t left = s->e->csize - s->in_pos;
            size_t n = left < sizeof s->in ? (size_t)left : sizeof s->in;
            if (n) {
                if (rsrc_read(s->z->src, s->in, n, s->e->data_off + s->in_pos) < 0)
                    return -1;
                s->in_pos += n;
                s->zs.next_in = s->in;
                s->zs.avail_in = (uInt)n;
            }
        }
        int r = inflate(&s->zs, Z_NO_FLUSH);
        if (r == Z_STREAM_END) {
            s->done = 1;
            break;
        }
        if (r != Z_OK && !(r == Z_BUF_ERROR && s->zs.avail_in == 0 && s->in_pos < s->e->csize))
            return -1;
        if (r == Z_BUF_ERROR && s->in_pos >= s->e->csize && !s->zs.avail_in)
            return -1;
    }
    long got = (long)(want - s->zs.avail_out);
    s->out_pos += (uint64_t)got;
    return got;
}

void zstream_close(zstream *s)
{
    if (!s)
        return;
    if (s->inflating)
        inflateEnd(&s->zs);
    free(s);
}

int zipr_read_all(zipr *z, zip_entry *e, buf_t *out, size_t limit)
{
    if (limit && e->usize > limit)
        return -1;
    zstream *s = zstream_open(z, e);
    if (!s)
        return -1;
    buf_reserve(out, (size_t)e->usize);
    unsigned char tmp[65536];
    long n;
    while ((n = zstream_read(s, tmp, sizeof tmp)) > 0) {
        if (limit && out->len + (size_t)n > limit) {
            zstream_close(s);
            return -1;
        }
        buf_put(out, tmp, (size_t)n);
    }
    zstream_close(s);
    if (n < 0 || out->len != e->usize) {
        warn("%s: %s: corrupt compressed data", z->path, e->name);
        return -1;
    }
    return 0;
}

rsrc *zipr_open_entry(zipr *z, zip_entry *e)
{
    if (check_supported(z, e) < 0)
        return NULL;
    char *label = xasprintf("%s:%s", path_basename(z->path), e->name);
    if (e->method == 0) {
        rsrc *r = rsrc_open_slice(z->src, e->data_off, e->usize, label);
        free(label);
        return r;
    }
    note("  extracting  %s (%llu MiB) to a temporary file", e->name, (unsigned long long)(e->usize >> 20));
    int fd = temp_fd();
    zstream *s = zstream_open(z, e);
    unsigned char *buf = xmalloc(1u << 20);
    long n;
    uint64_t total = 0;
    while ((n = zstream_read(s, buf, 1u << 20)) > 0) {
        size_t done = 0;
        while (done < (size_t)n) {
            ssize_t w = write(fd, buf + done, (size_t)n - done);
            if (w < 0) {
                if (errno == EINTR)
                    continue;
                die("writing a temporary file failed: %s", strerror(errno));
            }
            done += (size_t)w;
        }
        total += (uint64_t)n;
    }
    free(buf);
    zstream_close(s);
    if (n < 0 || total != e->usize) {
        close(fd);
        free(label);
        warn("%s: %s: corrupt compressed data", z->path, e->name);
        return NULL;
    }
    rsrc *r = rsrc_open_fd(fd, label);
    free(label);
    return r;
}
