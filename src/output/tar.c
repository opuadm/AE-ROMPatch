#include "output/tar.h"

#include <stdlib.h>
#include <string.h>
#include <zlib.h>

#include "core/util.h"

struct tarw {
    FILE *fp;
    gzFile gz;
    int owns_fp;
    uint64_t bytes;
    uint64_t remaining;
    uint64_t written_in_entry;
    int in_file;
    int failed;
};

static int out(tarw *t, const void *p, size_t n)
{
    if (t->failed)
        return -1;
    if (!n)
        return 0;
    if (t->gz) {
        const unsigned char *b = p;
        while (n) {
            unsigned chunk = n > (1u << 30) ? (1u << 30) : (unsigned)n;
            if (gzwrite(t->gz, b, chunk) != (int)chunk) {
                t->failed = 1;
                return -1;
            }
            b += chunk;
            n -= chunk;
            t->bytes += chunk;
        }
        return 0;
    }
    if (fwrite(p, 1, n, t->fp) != n) {
        t->failed = 1;
        return -1;
    }
    t->bytes += n;
    return 0;
}

tarw *tarw_open(const char *path, int gzip_level)
{
    tarw *t = xcalloc(1, sizeof *t);
    if (gzip_level > 0) {
        char mode[8];
        snprintf(mode, sizeof mode, "wb%d", gzip_level > 9 ? 9 : gzip_level);
        t->gz = gzopen(path, mode);
        if (!t->gz) {
            free(t);
            return NULL;
        }
        gzbuffer(t->gz, 1u << 20);
    } else {
        t->fp = fopen(path, "wb");
        if (!t->fp) {
            free(t);
            return NULL;
        }
        setvbuf(t->fp, NULL, _IOFBF, 1u << 20);
        t->owns_fp = 1;
    }
    return t;
}

tarw *tarw_open_fp(FILE *fp)
{
    tarw *t = xcalloc(1, sizeof *t);
    t->fp = fp;
    return t;
}

static void octal(char *field, size_t width, uint64_t v)
{
    uint64_t limit = 1;
    for (size_t i = 0; i < width - 1; i++)
        limit *= 8;
    if (v < limit) {
        snprintf(field, width, "%0*llo", (int)(width - 1), (unsigned long long)v);
        return;
    }
    memset(field, 0, width);
    field[0] = (char)0x80;
    for (size_t i = width - 1; i > 0 && v; i--) {
        field[i] = (char)(v & 0xff);
        v >>= 8;
    }
}

static int header(tarw *t, const char *name, char type, uint64_t size, uint32_t mode, uint32_t uid, uint32_t gid,
                  int64_t mtime, const char *link)
{
    unsigned char h[512];
    memset(h, 0, sizeof h);
    size_t nl = strlen(name);
    if (nl > 100) {
        if (header(t, "././@LongLink", 'L', nl + 1, 0644, 0, 0, 0, NULL) < 0)
            return -1;
        if (out(t, name, nl + 1) < 0)
            return -1;
        size_t pad = (512 - ((nl + 1) % 512)) % 512;
        unsigned char z[512] = {0};
        if (out(t, z, pad) < 0)
            return -1;
    }
    if (link && strlen(link) > 100) {
        size_t ll = strlen(link);
        if (header(t, "././@LongLink", 'K', ll + 1, 0644, 0, 0, 0, NULL) < 0)
            return -1;
        if (out(t, link, ll + 1) < 0)
            return -1;
        size_t pad = (512 - ((ll + 1) % 512)) % 512;
        unsigned char z[512] = {0};
        if (out(t, z, pad) < 0)
            return -1;
    }
    memcpy(h, name, nl > 100 ? 100 : nl);
    octal((char *)h + 100, 8, mode & 07777);
    octal((char *)h + 108, 8, uid);
    octal((char *)h + 116, 8, gid);
    octal((char *)h + 124, 12, size);
    octal((char *)h + 136, 12, mtime < 0 ? 0 : (uint64_t)mtime);
    h[156] = (unsigned char)type;
    if (link)
        memcpy(h + 157, link, strlen(link) > 100 ? 100 : strlen(link));
    memcpy(h + 257, "ustar", 6);
    memcpy(h + 263, "00", 2);
    memcpy(h + 265, uid == 0 ? "root" : "", uid == 0 ? 4 : 0);
    memcpy(h + 297, gid == 0 ? "root" : "", gid == 0 ? 4 : 0);
    memset(h + 148, ' ', 8);
    unsigned sum = 0;
    for (int i = 0; i < 512; i++)
        sum += h[i];
    snprintf((char *)h + 148, 8, "%06o", sum);
    h[155] = ' ';
    return out(t, h, sizeof h);
}

int tarw_dir(tarw *t, const char *name, uint32_t mode, uint32_t uid, uint32_t gid, int64_t mtime)
{
    char *n = xasprintf("%s/", name);
    int r = header(t, n, '5', 0, mode, uid, gid, mtime, NULL);
    free(n);
    return r;
}

int tarw_symlink(tarw *t, const char *name, const char *target, uint32_t mode, uint32_t uid, uint32_t gid,
                 int64_t mtime)
{
    return header(t, name, '2', 0, mode ? mode : 0777, uid, gid, mtime, target);
}

int tarw_file_begin(tarw *t, const char *name, uint64_t size, uint32_t mode, uint32_t uid, uint32_t gid,
                    int64_t mtime)
{
    if (header(t, name, '0', size, mode, uid, gid, mtime, NULL) < 0)
        return -1;
    t->in_file = 1;
    t->remaining = size;
    t->written_in_entry = 0;
    return 0;
}

int tarw_write(tarw *t, const void *data, size_t len)
{
    if (!t->in_file || len > t->remaining) {
        t->failed = 1;
        return -1;
    }
    t->remaining -= len;
    t->written_in_entry += len;
    return out(t, data, len);
}

int tarw_file_end(tarw *t)
{
    if (!t->in_file || t->remaining) {
        t->failed = 1;
        return -1;
    }
    t->in_file = 0;
    size_t pad = (size_t)((512 - (t->written_in_entry % 512)) % 512);
    unsigned char z[512] = {0};
    return out(t, z, pad);
}

int tarw_close(tarw *t)
{
    unsigned char z[1024] = {0};
    int r = out(t, z, sizeof z);
    if (t->gz) {
        if (gzclose(t->gz) != Z_OK)
            r = -1;
    } else if (t->owns_fp) {
        if (fclose(t->fp) != 0)
            r = -1;
    } else if (fflush(t->fp) != 0) {
        r = -1;
    }
    if (t->failed)
        r = -1;
    free(t);
    return r;
}

uint64_t tarw_bytes(const tarw *t)
{
    return t->bytes;
}
