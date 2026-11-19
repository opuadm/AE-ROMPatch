#include "formats/cpio.h"

#include <stdlib.h>
#include <string.h>

static int hex8(const unsigned char *p, uint32_t *v)
{
    uint32_t r = 0;
    for (int i = 0; i < 8; i++) {
        int c = p[i], d;
        if (c >= '0' && c <= '9')
            d = c - '0';
        else if (c >= 'a' && c <= 'f')
            d = c - 'a' + 10;
        else if (c >= 'A' && c <= 'F')
            d = c - 'A' + 10;
        else
            return -1;
        r = (r << 4) | (uint32_t)d;
    }
    *v = r;
    return 0;
}

int cpio_parse(const unsigned char *d, size_t len, cpio_list *out, char *err, size_t errlen)
{
    size_t off = 0;
    int trailer = 0;
    while (off + 110 <= len) {
        if (memcmp(d + off, "070701", 6) && memcmp(d + off, "070702", 6)) {
            if (d[off] == 0) {
                off++;
                continue;
            }
            break;
        }
        uint32_t f[13];
        for (int i = 0; i < 13; i++) {
            if (hex8(d + off + 6 + i * 8, &f[i]) < 0) {
                snprintf(err, errlen, "corrupt cpio header at %zu", off);
                return -1;
            }
        }
        uint32_t mode = f[1], uid = f[2], gid = f[3], mtime = f[5], size = f[6], namesize = f[11];
        size_t name_at = off + 110;
        if (namesize == 0 || namesize > 4096 || name_at + namesize > len) {
            snprintf(err, errlen, "corrupt cpio name at %zu", off);
            return -1;
        }
        const char *name = (const char *)d + name_at;
        size_t nlen = strnlen(name, namesize);
        size_t data_at = (name_at + namesize + 3) & ~(size_t)3;
        if (nlen == 10 && !memcmp(name, "TRAILER!!!", 10)) {
            trailer = 1;
            break;
        }
        if (data_at + size > len) {
            snprintf(err, errlen, "truncated cpio archive");
            return -1;
        }
        while (nlen >= 2 && name[0] == '.' && name[1] == '/') {
            name += 2;
            nlen -= 2;
        }
        while (nlen && name[0] == '/') {
            name++;
            nlen--;
        }
        while (nlen && name[nlen - 1] == '/')
            nlen--;
        if (nlen && !(nlen == 1 && name[0] == '.')) {
            if (out->n == out->cap) {
                out->cap = out->cap ? out->cap * 2 : 64;
                out->e = xrealloc(out->e, out->cap * sizeof(cpio_entry));
            }
            cpio_entry *e = &out->e[out->n++];
            e->name = xstrndup(name, nlen);
            e->mode = mode;
            e->uid = uid;
            e->gid = gid;
            e->mtime = mtime;
            size_t sz = size;
            if ((mode & 0xF000) == 0xA000)
                while (sz && d[data_at + sz - 1] == 0)
                    sz--;
            e->data = xmalloc(sz + 1);
            memcpy(e->data, d + data_at, sz);
            e->data[sz] = 0;
            e->size = sz;
        }
        off = (data_at + size + 3) & ~(size_t)3;
    }
    if (!trailer && !out->n) {
        snprintf(err, errlen, "not a cpio (newc) archive");
        return -1;
    }
    return 0;
}

void cpio_free(cpio_list *l)
{
    for (size_t i = 0; i < l->n; i++) {
        free(l->e[i].name);
        free(l->e[i].data);
    }
    free(l->e);
    l->e = NULL;
    l->n = l->cap = 0;
}

const cpio_entry *cpio_find(const cpio_list *l, const char *name)
{
    for (size_t i = 0; i < l->n; i++)
        if (!strcmp(l->e[i].name, name))
            return &l->e[i];
    return NULL;
}

static void pad4(buf_t *out)
{
    while (out->len & 3)
        buf_putc(out, 0);
}

void cpio_write_entry(buf_t *out, uint32_t ino, const char *name, uint32_t mode, uint32_t uid, uint32_t gid,
                      int64_t mtime, const void *data, size_t size)
{
    size_t namesize = strlen(name) + 1;
    uint32_t nlink = (mode & 0xF000) == 0x4000 ? 2 : 1;
    buf_printf(out, "070701%08X%08X%08X%08X%08X%08X%08X%08X%08X%08X%08X%08X%08X", ino, mode, uid, gid, nlink,
               (uint32_t)(mtime < 0 ? 0 : mtime), (uint32_t)size, 0u, 0u, 0u, 0u, (uint32_t)namesize, 0u);
    buf_put(out, name, namesize);
    pad4(out);
    if (size)
        buf_put(out, data, size);
    pad4(out);
}

void cpio_write_trailer(buf_t *out, uint32_t ino)
{
    cpio_write_entry(out, ino, "TRAILER!!!", 0, 0, 0, 0, NULL, 0);
}
