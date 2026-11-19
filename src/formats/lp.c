#include "formats/lp.h"

#include <stdlib.h>
#include <string.h>

#include "core/util.h"

#define LP_GEOMETRY_MAGIC 0x616c4467U
#define LP_HEADER_MAGIC 0x414C5030U
#define LP_RESERVED 4096
#define LP_GEOMETRY_SIZE 4096
#define SECTOR 512

int lp_probe(rsrc *src)
{
    unsigned char m[4];
    return src->size > LP_RESERVED + LP_GEOMETRY_SIZE * 2 && rsrc_read(src, m, 4, LP_RESERVED) == 0 &&
           le32(m) == LP_GEOMETRY_MAGIC;
}

int lp_read(rsrc *src, lp_table *t, char *err, size_t errlen)
{
    memset(t, 0, sizeof *t);
    unsigned char g[52];
    if (rsrc_read(src, g, sizeof g, LP_RESERVED) < 0 || le32(g) != LP_GEOMETRY_MAGIC) {
        snprintf(err, errlen, "no dynamic partition metadata");
        return -1;
    }
    uint32_t max_size = le32(g + 40);
    uint64_t hoff = LP_RESERVED + LP_GEOMETRY_SIZE * 2;
    unsigned char h[256];
    memset(h, 0, sizeof h);
    if (rsrc_read(src, h, 128, hoff) < 0 || le32(h) != LP_HEADER_MAGIC) {
        snprintf(err, errlen, "corrupt dynamic partition metadata header");
        return -1;
    }
    uint32_t header_size = le32(h + 8);
    uint32_t tables_size = le32(h + 44);
    if (header_size < 128 || header_size > 4096 || tables_size > max_size || tables_size > (16u << 20)) {
        snprintf(err, errlen, "corrupt dynamic partition metadata sizes");
        return -1;
    }
    unsigned char *tab = xmalloc(tables_size + 1);
    if (rsrc_read(src, tab, tables_size, hoff + header_size) < 0) {
        free(tab);
        snprintf(err, errlen, "cannot read dynamic partition tables");
        return -1;
    }
    uint32_t p_off = le32(h + 80), p_n = le32(h + 84), p_sz = le32(h + 88);
    uint32_t e_off = le32(h + 92), e_n = le32(h + 96), e_sz = le32(h + 100);
    uint32_t b_n = le32(h + 120);
    if (p_sz < 52 || e_sz < 24 || (uint64_t)p_off + (uint64_t)p_n * p_sz > tables_size ||
        (uint64_t)e_off + (uint64_t)e_n * e_sz > tables_size) {
        free(tab);
        snprintf(err, errlen, "corrupt dynamic partition tables");
        return -1;
    }
    if (b_n > 1)
        debug("super: %u block devices; only partitions on the first one are read", b_n);
    t->parts = xcalloc(p_n ? p_n : 1, sizeof(lp_part));
    for (uint32_t i = 0; i < p_n; i++) {
        const unsigned char *pe = tab + p_off + (size_t)i * p_sz;
        lp_part *p = &t->parts[t->n];
        memcpy(p->name, pe, 36);
        p->name[36] = 0;
        uint32_t first = le32(pe + 40), num = le32(pe + 44);
        if ((uint64_t)first + num > e_n)
            continue;
        p->ext = xcalloc(num ? num : 1, sizeof(lp_extent));
        int ok = 1;
        for (uint32_t k = 0; k < num; k++) {
            const unsigned char *ee = tab + e_off + (size_t)(first + k) * e_sz;
            uint64_t sectors = le64(ee);
            uint32_t type = le32(ee + 8);
            uint64_t data = le64(ee + 12);
            uint32_t source = le32(ee + 20);
            if (type == 0 && source != 0)
                ok = 0;
            p->ext[k].len = sectors * SECTOR;
            p->ext[k].zero = type != 0;
            p->ext[k].off = data * SECTOR;
            p->size += sectors * SECTOR;
        }
        p->n = num;
        if (!ok) {
            debug("super: partition %s lives on another block device; skipped", p->name);
            free(p->ext);
            memset(p, 0, sizeof *p);
            continue;
        }
        t->n++;
    }
    free(tab);
    return 0;
}

void lp_free(lp_table *t)
{
    for (size_t i = 0; i < t->n; i++)
        free(t->parts[i].ext);
    free(t->parts);
    memset(t, 0, sizeof *t);
}

typedef struct {
    rsrc *base;
    lp_extent *ext;
    uint64_t *start;
    size_t n;
} ext_priv;

static int ext_pread(rsrc *s, void *buf, size_t len, uint64_t off)
{
    ext_priv *p = s->priv;
    unsigned char *b = buf;
    if (off > s->size || len > s->size - off) {
        memset(buf, 0, len);
        return -1;
    }
    size_t lo = 0, hi = p->n;
    while (lo + 1 < hi) {
        size_t mid = (lo + hi) / 2;
        if (p->start[mid] <= off)
            lo = mid;
        else
            hi = mid;
    }
    for (size_t i = lo; len && i < p->n; i++) {
        uint64_t within = off - p->start[i];
        if (within >= p->ext[i].len)
            continue;
        size_t take = (size_t)(p->ext[i].len - within < len ? p->ext[i].len - within : len);
        if (p->ext[i].zero)
            memset(b, 0, take);
        else if (rsrc_read(p->base, b, take, p->ext[i].off + within) < 0)
            return -1;
        b += take;
        off += take;
        len -= take;
    }
    return len ? -1 : 0;
}

static void ext_close(rsrc *s)
{
    ext_priv *p = s->priv;
    free(p->ext);
    free(p->start);
    free(p);
}

rsrc *lp_open_partition(rsrc *src, const lp_part *part)
{
    ext_priv *p = xcalloc(1, sizeof *p);
    p->base = src;
    p->n = part->n;
    p->ext = xcalloc(part->n ? part->n : 1, sizeof(lp_extent));
    p->start = xcalloc(part->n ? part->n : 1, sizeof(uint64_t));
    uint64_t pos = 0;
    for (size_t i = 0; i < part->n; i++) {
        p->ext[i] = part->ext[i];
        p->start[i] = pos;
        pos += part->ext[i].len;
    }
    rsrc *s = xcalloc(1, sizeof *s);
    s->priv = p;
    s->size = pos;
    s->name = xasprintf("super:%s", part->name);
    s->pread = ext_pread;
    s->close = ext_close;
    return s;
}
