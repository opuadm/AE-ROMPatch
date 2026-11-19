#include "core/about.h"
#include "core/rsrc.h"

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "core/util.h"

#define SPARSE_MAGIC 0xed26ff3aU
#define CHUNK_RAW 0xCAC1
#define CHUNK_FILL 0xCAC2
#define CHUNK_DONT_CARE 0xCAC3
#define CHUNK_CRC32 0xCAC4

typedef struct {
    int fd;
} file_priv;

static int file_pread(rsrc *s, void *buf, size_t len, uint64_t off)
{
    file_priv *p = s->priv;
    unsigned char *b = buf;
    while (len) {
        ssize_t n = pread(p->fd, b, len, (off_t)off);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        if (n == 0) {
            memset(b, 0, len);
            return -1;
        }
        b += n;
        len -= (size_t)n;
        off += (uint64_t)n;
    }
    return 0;
}

static void file_close(rsrc *s)
{
    file_priv *p = s->priv;
    close(p->fd);
    free(p);
}

rsrc *rsrc_open_fd(int fd, const char *name)
{
    struct stat st;
    if (fstat(fd, &st) < 0)
        return NULL;
    rsrc *s = xcalloc(1, sizeof *s);
    file_priv *p = xcalloc(1, sizeof *p);
    p->fd = fd;
    s->priv = p;
    s->size = (uint64_t)st.st_size;
    s->name = xstrdup(name);
    s->pread = file_pread;
    s->close = file_close;
    return s;
}

static char *temp_default;

void temp_dir_default(const char *dir)
{
    free(temp_default);
    temp_default = dir && *dir ? xstrdup(dir) : NULL;
}

const char *temp_dir(void)
{
    const char *dir = getenv("TMPDIR");
    if (dir && *dir)
        return dir;
    if (temp_default)
        return temp_default;
    return "/var/tmp";
}

int temp_fd(void)
{
    const char *dir = temp_dir();
    char *path = xasprintf("%s/" AEP_BIN "-XXXXXX", dir);
    int fd = mkstemp(path);
    if (fd < 0)
        die("cannot create a temporary file in %s: %s (set TMPDIR to a folder with free space)", dir, strerror(errno));
    unlink(path);
    free(path);
    return fd;
}

rsrc *rsrc_open_file(const char *path)
{
    struct stat st;
    int fd = open(path, O_RDONLY);
    if (fd < 0)
        return NULL;
    if (fstat(fd, &st) < 0 || !S_ISREG(st.st_mode)) {
        close(fd);
        errno = EINVAL;
        return NULL;
    }
    rsrc *s = xcalloc(1, sizeof *s);
    file_priv *p = xcalloc(1, sizeof *p);
    p->fd = fd;
    s->priv = p;
    s->size = (uint64_t)st.st_size;
    s->name = xstrdup(path);
    s->pread = file_pread;
    s->close = file_close;
    return s;
}

typedef struct {
    const unsigned char *data;
} mem_priv;

static int mem_pread(rsrc *s, void *buf, size_t len, uint64_t off)
{
    mem_priv *p = s->priv;
    if (off > s->size || len > s->size - off) {
        memset(buf, 0, len);
        return -1;
    }
    memcpy(buf, p->data + off, len);
    return 0;
}

static void mem_close(rsrc *s)
{
    free(s->priv);
}

rsrc *rsrc_open_mem(const unsigned char *data, size_t len, const char *name)
{
    rsrc *s = xcalloc(1, sizeof *s);
    mem_priv *p = xcalloc(1, sizeof *p);
    p->data = data;
    s->priv = p;
    s->size = len;
    s->name = xstrdup(name);
    s->pread = mem_pread;
    s->close = mem_close;
    return s;
}

typedef struct {
    uint64_t out_off;
    uint64_t len;
    uint64_t in_off;
    uint32_t fill;
    int type;
} chunk;

typedef struct {
    rsrc *base;
    chunk *chunks;
    size_t n;
} sparse_priv;

int sparse_probe(rsrc *s)
{
    unsigned char h[28];
    if (s->size < 28 || rsrc_read(s, h, 28, 0) < 0)
        return 0;
    return le32(h) == SPARSE_MAGIC && le16(h + 4) == 1;
}

static int sparse_pread(rsrc *s, void *buf, size_t len, uint64_t off)
{
    sparse_priv *p = s->priv;
    unsigned char *b = buf;
    if (off > s->size || len > s->size - off) {
        memset(buf, 0, len);
        return -1;
    }
    size_t lo = 0, hi = p->n;
    while (lo + 1 < hi) {
        size_t mid = (lo + hi) / 2;
        if (p->chunks[mid].out_off <= off)
            lo = mid;
        else
            hi = mid;
    }
    size_t i = lo;
    while (len) {
        if (i >= p->n) {
            memset(b, 0, len);
            return 0;
        }
        chunk *c = &p->chunks[i];
        if (off < c->out_off || off >= c->out_off + c->len) {
            i++;
            continue;
        }
        uint64_t within = off - c->out_off;
        size_t take = (size_t)((c->len - within) < len ? (c->len - within) : len);
        if (c->type == CHUNK_RAW) {
            if (rsrc_read(p->base, b, take, c->in_off + within) < 0)
                return -1;
        } else if (c->type == CHUNK_FILL) {
            unsigned char pat[4];
            put_le32(pat, c->fill);
            for (size_t k = 0; k < take; k++)
                b[k] = pat[(within + k) & 3];
        } else {
            memset(b, 0, take);
        }
        b += take;
        len -= take;
        off += take;
        i++;
    }
    return 0;
}

static void sparse_close(rsrc *s)
{
    sparse_priv *p = s->priv;
    rsrc_close(p->base);
    free(p->chunks);
    free(p);
}

rsrc *rsrc_open_sparse(rsrc *base)
{
    unsigned char h[28];
    if (rsrc_read(base, h, 28, 0) < 0 || le32(h) != SPARSE_MAGIC)
        return NULL;
    uint16_t file_hdr = le16(h + 8);
    uint16_t chunk_hdr = le16(h + 10);
    uint32_t blk = le32(h + 12);
    uint32_t total_blks = le32(h + 16);
    uint32_t total_chunks = le32(h + 20);
    if (file_hdr < 28 || chunk_hdr < 12 || blk == 0 || (blk & 3))
        return NULL;
    sparse_priv *p = xcalloc(1, sizeof *p);
    p->base = base;
    p->chunks = xcalloc(total_chunks ? total_chunks : 1, sizeof(chunk));
    uint64_t in = file_hdr, out = 0;
    for (uint32_t i = 0; i < total_chunks; i++) {
        unsigned char ch[12];
        if (rsrc_read(base, ch, 12, in) < 0)
            goto bad;
        uint16_t type = le16(ch);
        uint64_t blocks = le32(ch + 4);
        uint64_t total = le32(ch + 8);
        uint64_t bytes = blocks * blk;
        uint64_t data = in + chunk_hdr;
        chunk c = {out, bytes, data, 0, type};
        switch (type) {
        case CHUNK_RAW:
            if (total != chunk_hdr + bytes)
                goto bad;
            break;
        case CHUNK_FILL: {
            unsigned char f[4];
            if (total < chunk_hdr + 4u || rsrc_read(base, f, 4, data) < 0)
                goto bad;
            c.fill = le32(f);
            break;
        }
        case CHUNK_DONT_CARE:
            break;
        case CHUNK_CRC32:
            c.len = 0;
            break;
        default:
            goto bad;
        }
        if (c.len)
            p->chunks[p->n++] = c;
        out += c.len;
        in += total;
    }
    if (out != (uint64_t)total_blks * blk)
        debug("sparse: chunks cover %llu bytes, header says %llu", (unsigned long long)out,
              (unsigned long long)total_blks * blk);
    rsrc *s = xcalloc(1, sizeof *s);
    s->priv = p;
    s->size = (uint64_t)total_blks * blk;
    s->name = xasprintf("%s (sparse)", base->name);
    s->pread = sparse_pread;
    s->close = sparse_close;
    return s;
bad:
    free(p->chunks);
    free(p);
    return NULL;
}

rsrc *rsrc_open_auto(const char *path)
{
    rsrc *s = rsrc_open_file(path);
    if (!s)
        return NULL;
    if (sparse_probe(s)) {
        rsrc *sp = rsrc_open_sparse(s);
        if (!sp) {
            rsrc_close(s);
            errno = EINVAL;
            return NULL;
        }
        return sp;
    }
    return s;
}

int rsrc_read(rsrc *s, void *buf, size_t len, uint64_t off)
{
    if (!len)
        return 0;
    return s->pread(s, buf, len, off);
}

void rsrc_close(rsrc *s)
{
    if (!s)
        return;
    if (s->close)
        s->close(s);
    free(s->name);
    free(s);
}
