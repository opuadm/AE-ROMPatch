#include "formats/bootimg.h"

#include <stdlib.h>
#include <string.h>

#include "core/codec.h"

#define MTK_MAGIC 0x58881688U

static size_t align_up(size_t n, size_t a)
{
    return (n + a - 1) / a * a;
}

int bootimg_probe(const unsigned char *d, size_t len)
{
    if (len >= 8 && !memcmp(d, "ANDROID!", 8))
        return 1;
    if (len >= 264 && !memcmp(d + 256, "ANDROID!", 8))
        return 1;
    return 0;
}

static int take(const unsigned char *d, size_t len, size_t off, size_t size, unsigned char **out, size_t *out_size,
                int *mtk)
{
    if (size == 0) {
        *out = NULL;
        *out_size = 0;
        return 0;
    }
    if (off > len || size > len - off)
        return -1;
    if (size > 512 && le32(d + off) == MTK_MAGIC) {
        off += 512;
        size -= 512;
        *mtk = 1;
    }
    *out = xmalloc(size);
    memcpy(*out, d + off, size);
    *out_size = size;
    return 0;
}

int bootimg_parse(const unsigned char *d, size_t len, bootimg *b, char *err, size_t errlen)
{
    memset(b, 0, sizeof *b);
    if (len >= 264 && memcmp(d, "ANDROID!", 8) && !memcmp(d + 256, "ANDROID!", 8)) {
        d += 256;
        len -= 256;
        b->htc_signed = 1;
    }
    if (len < 1648 || memcmp(d, "ANDROID!", 8)) {
        snprintf(err, errlen, "not an Android boot image");
        return -1;
    }
    uint32_t hv = le32(d + 40);
    size_t koff, roff, ksize, rsize;
    if ((hv == 3 || hv == 4) && le32(d + 20) >= 1024 && le32(d + 20) <= 4096) {
        b->header_version = (int)hv;
        b->page_size = 4096;
        ksize = le32(d + 8);
        rsize = le32(d + 12);
        b->os_version = le32(d + 16);
        memcpy(b->cmdline, d + 44, 1536);
        b->cmdline[1536] = 0;
        koff = 4096;
        roff = koff + align_up(ksize, 4096);
    } else {
        b->header_version = hv <= 2 ? (int)hv : 0;
        ksize = le32(d + 8);
        b->kernel_addr = le32(d + 12);
        rsize = le32(d + 16);
        b->ramdisk_addr = le32(d + 20);
        b->second_addr = le32(d + 28);
        b->tags_addr = le32(d + 32);
        b->page_size = le32(d + 36);
        if (b->page_size < 2048 || b->page_size > 131072 || (b->page_size & (b->page_size - 1)))
            b->page_size = 2048;
        b->os_version = le32(d + 44);
        memcpy(b->name, d + 48, 16);
        b->name[16] = 0;
        size_t c1 = strnlen((const char *)d + 64, 512);
        memcpy(b->cmdline, d + 64, c1);
        size_t c2 = strnlen((const char *)d + 608, 1024);
        memcpy(b->cmdline + c1, d + 608, c2);
        b->cmdline[c1 + c2] = 0;
        koff = b->page_size;
        roff = koff + align_up(ksize, b->page_size);
    }
    if (take(d, len, koff, ksize, &b->kernel, &b->kernel_size, &b->mtk_header) < 0 ||
        take(d, len, roff, rsize, &b->ramdisk, &b->ramdisk_size, &b->mtk_header) < 0) {
        bootimg_free(b);
        snprintf(err, errlen, "truncated boot image");
        return -1;
    }
    return 0;
}

void bootimg_free(bootimg *b)
{
    free(b->kernel);
    free(b->ramdisk);
    b->kernel = b->ramdisk = NULL;
    b->kernel_size = b->ramdisk_size = 0;
}

void bootimg_build_v0(const bootimg *t, const unsigned char *kernel, size_t kernel_size,
                      const unsigned char *ramdisk, size_t ramdisk_size, buf_t *out)
{
    uint32_t page = 2048;
    uint32_t kaddr = 0x10008000, raddr = 0x11000000, saddr = 0x10f00000, taddr = 0x10000100;
    if (t && t->header_version <= 2) {
        page = t->page_size ? t->page_size : 2048;
        if (t->kernel_addr)
            kaddr = t->kernel_addr;
        if (t->ramdisk_addr)
            raddr = t->ramdisk_addr;
        if (t->second_addr)
            saddr = t->second_addr;
        if (t->tags_addr)
            taddr = t->tags_addr;
    }
    unsigned char *h = xcalloc(1, page);
    memcpy(h, "ANDROID!", 8);
    put_le32(h + 8, (uint32_t)kernel_size);
    put_le32(h + 12, kaddr);
    put_le32(h + 16, (uint32_t)ramdisk_size);
    put_le32(h + 20, raddr);
    put_le32(h + 24, 0);
    put_le32(h + 28, saddr);
    put_le32(h + 32, taddr);
    put_le32(h + 36, page);
    put_le32(h + 40, 0);
    put_le32(h + 44, t ? t->os_version : 0);
    if (t) {
        memcpy(h + 48, t->name, strnlen(t->name, 16));
        size_t cl = strlen(t->cmdline);
        size_t c1 = cl > 511 ? 511 : cl;
        memcpy(h + 64, t->cmdline, c1);
        if (cl > 511) {
            size_t c2 = cl - 511;
            if (c2 > 1023)
                c2 = 1023;
            memcpy(h + 608, t->cmdline + 511, c2);
        }
    }
    buf_put(out, h, page);
    free(h);
    static const unsigned char zeros[4096];
    if (kernel_size) {
        buf_put(out, kernel, kernel_size);
        size_t pad = align_up(kernel_size, page) - kernel_size;
        while (pad) {
            size_t n = pad > sizeof zeros ? sizeof zeros : pad;
            buf_put(out, zeros, n);
            pad -= n;
        }
    }
    if (ramdisk_size) {
        buf_put(out, ramdisk, ramdisk_size);
        size_t pad = align_up(ramdisk_size, page) - ramdisk_size;
        while (pad) {
            size_t n = pad > sizeof zeros ? sizeof zeros : pad;
            buf_put(out, zeros, n);
            pad -= n;
        }
    }
}

static const char *find_banner(const unsigned char *d, size_t len, char *buf, size_t blen)
{
    static const char tag[] = "Linux version ";
    size_t tl = sizeof tag - 1;
    for (size_t i = 0; i + tl < len; i++) {
        if (d[i] == 'L' && !memcmp(d + i, tag, tl) && i + tl < len && d[i + tl] >= '0' && d[i + tl] <= '9') {
            size_t j = i, o = 0;
            while (j < len && d[j] && d[j] != '\n' && o + 1 < blen)
                buf[o++] = (char)d[j++];
            buf[o] = 0;
            return buf;
        }
    }
    return NULL;
}

const char *bootimg_kernel_banner(const bootimg *b, char *buf, size_t len)
{
    if (!b->kernel_size)
        return NULL;
    if (find_banner(b->kernel, b->kernel_size, buf, len))
        return buf;
    for (size_t i = 0; i + 10 < b->kernel_size && i < (4u << 20); i++) {
        if (b->kernel[i] == 0x1f && b->kernel[i + 1] == 0x8b && b->kernel[i + 2] == 0x08) {
            buf_t out = {0};
            char err[128];
            if (codec_decompress(b->kernel + i, b->kernel_size - i, &out, 256u << 20, err, sizeof err) == 0 &&
                find_banner(out.data, out.len, buf, len)) {
                buf_free(&out);
                return buf;
            }
            buf_free(&out);
        }
    }
    return NULL;
}
