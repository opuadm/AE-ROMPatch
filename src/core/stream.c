#include "core/stream.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <zlib.h>

#include "core/codec.h"
#include "core/util.h"

#ifdef HAVE_LZMA
#include <lzma.h>
#endif
#ifdef HAVE_BZ2
#include <bzlib.h>
#endif
#ifdef HAVE_ZSTD
#include <zstd.h>
#endif

#define CHUNK (1u << 20)

void sreader_init(sreader *r, seq_read_fn rd, void *ctx, uint64_t limit)
{
    memset(r, 0, sizeof *r);
    r->rd = rd;
    r->ctx = ctx;
    r->limit = limit;
}

void sreader_free(sreader *r)
{
    free(r->peek);
    r->peek = NULL;
    r->npeek = r->ppos = 0;
}

static long raw_read(sreader *r, void *buf, size_t len)
{
    if (r->limit != UINT64_MAX) {
        uint64_t left = r->limit - r->consumed;
        if (!left)
            return 0;
        if (len > left)
            len = (size_t)left;
    }
    long n = r->rd(r->ctx, buf, len);
    if (n > 0)
        r->consumed += (uint64_t)n;
    return n;
}

int sreader_peek(sreader *r, unsigned char *buf, size_t len)
{
    if (!r->peek) {
        r->peek = xmalloc(len);
        while (r->npeek < len) {
            long n = raw_read(r, r->peek + r->npeek, len - r->npeek);
            if (n < 0)
                return -1;
            if (n == 0)
                break;
            r->npeek += (size_t)n;
        }
    }
    memset(buf, 0, len);
    memcpy(buf, r->peek, r->npeek < len ? r->npeek : len);
    return (int)r->npeek;
}

long sreader_read(void *vr, void *buf, size_t len)
{
    sreader *r = vr;
    if (r->ppos < r->npeek) {
        size_t take = r->npeek - r->ppos < len ? r->npeek - r->ppos : len;
        memcpy(buf, r->peek + r->ppos, take);
        r->ppos += take;
        return (long)take;
    }
    return raw_read(r, buf, len);
}

int sreader_skip(sreader *r, uint64_t n)
{
    unsigned char tmp[65536];
    while (n) {
        long got = sreader_read(r, tmp, n > sizeof tmp ? sizeof tmp : (size_t)n);
        if (got <= 0)
            return -1;
        n -= (uint64_t)got;
    }
    return 0;
}

static int read_exact(sreader *r, void *buf, size_t len)
{
    unsigned char *b = buf;
    while (len) {
        long n = sreader_read(r, b, len);
        if (n <= 0)
            return -1;
        b += n;
        len -= (size_t)n;
    }
    return 0;
}

static void out_write(int fd, const void *buf, size_t len)
{
    const unsigned char *b = buf;
    while (len) {
        ssize_t n = write(fd, b, len);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            die("writing a temporary file failed: %s (set TMPDIR to a folder with more space)", strerror(errno));
        }
        b += n;
        len -= (size_t)n;
    }
}

static int do_raw(sreader *in, int fd)
{
    unsigned char *buf = xmalloc(CHUNK);
    long n;
    while ((n = sreader_read(in, buf, CHUNK)) > 0)
        out_write(fd, buf, (size_t)n);
    free(buf);
    return n < 0 ? -1 : 0;
}

static int do_gzip(sreader *in, int fd)
{
    z_stream z;
    memset(&z, 0, sizeof z);
    if (inflateInit2(&z, 15 + 32) != Z_OK)
        return -1;
    unsigned char *ib = xmalloc(CHUNK), *ob = xmalloc(CHUNK);
    int r = Z_OK;
    while (r != Z_STREAM_END) {
        if (!z.avail_in) {
            long n = sreader_read(in, ib, CHUNK);
            if (n <= 0)
                break;
            z.next_in = ib;
            z.avail_in = (uInt)n;
        }
        z.next_out = ob;
        z.avail_out = CHUNK;
        r = inflate(&z, Z_NO_FLUSH);
        if (r != Z_OK && r != Z_STREAM_END && r != Z_BUF_ERROR)
            break;
        out_write(fd, ob, CHUNK - z.avail_out);
    }
    inflateEnd(&z);
    free(ib);
    free(ob);
    return r == Z_STREAM_END ? 0 : -1;
}

static int do_lz4_frame(sreader *in, int fd)
{
    buf_t win = {0};
    unsigned char *blk = NULL;
    size_t blkcap = 0;
    int ok = 0;
    for (;;) {
        unsigned char h[4];
        long n = sreader_read(in, h, 4);
        if (n == 0) {
            ok = 1;
            break;
        }
        if (n < 4 && read_exact(in, h + n, 4 - (size_t)n) < 0)
            break;
        uint32_t magic = le32(h);
        if ((magic & 0xFFFFFFF0U) == 0x184D2A50U) {
            unsigned char s[4];
            if (read_exact(in, s, 4) < 0 || sreader_skip(in, le32(s)) < 0)
                break;
            continue;
        }
        if (magic != 0x184D2204U)
            break;
        unsigned char fd2[2];
        if (read_exact(in, fd2, 2) < 0)
            break;
        unsigned flg = fd2[0];
        int independent = (flg >> 5) & 1, block_ck = (flg >> 4) & 1, content_size = (flg >> 3) & 1;
        int content_ck = (flg >> 2) & 1, dict = flg & 1;
        if ((flg >> 6) != 1 || sreader_skip(in, (content_size ? 8 : 0) + (dict ? 4 : 0) + 1) < 0)
            break;
        int frame_ok = 0;
        win.len = 0;
        for (;;) {
            unsigned char bs[4];
            if (read_exact(in, bs, 4) < 0)
                break;
            uint32_t bsize = le32(bs);
            if (!bsize) {
                frame_ok = 1;
                break;
            }
            int raw = bsize >> 31;
            bsize &= 0x7fffffffU;
            if (bsize > (8u << 20))
                break;
            if (bsize > blkcap) {
                blkcap = bsize;
                blk = xrealloc(blk, blkcap);
            }
            if (read_exact(in, blk, bsize) < 0 || (block_ck && sreader_skip(in, 4) < 0))
                break;
            if (independent)
                win.len = 0;
            size_t start = win.len;
            if (raw)
                buf_put(&win, blk, bsize);
            else if (lz4_block_window(blk, bsize, &win, 0, independent ? 0 : 0) < 0)
                break;
            out_write(fd, win.data + start, win.len - start);
            if (win.len > 65536) {
                memmove(win.data, win.data + win.len - 65536, 65536);
                win.len = 65536;
            }
        }
        if (!frame_ok || (content_ck && sreader_skip(in, 4) < 0))
            break;
    }
    buf_free(&win);
    free(blk);
    return ok ? 0 : -1;
}

static int do_lz4_legacy(sreader *in, int fd)
{
    unsigned char *blk = NULL;
    size_t cap = 0;
    buf_t out = {0};
    if (sreader_skip(in, 4) < 0)
        return -1;
    int ok = 1;
    for (;;) {
        unsigned char s[4];
        long n = sreader_read(in, s, 4);
        if (n == 0)
            break;
        if (n < 4 && read_exact(in, s + n, 4 - (size_t)n) < 0)
            break;
        uint32_t clen = le32(s);
        if (clen == 0x184C2102U)
            continue;
        if (!clen || clen > (16u << 20))
            break;
        if (clen > cap) {
            cap = clen;
            blk = xrealloc(blk, cap);
        }
        if (read_exact(in, blk, clen) < 0) {
            ok = 0;
            break;
        }
        out.len = 0;
        if (lz4_block_window(blk, clen, &out, 0, 0) < 0) {
            ok = 0;
            break;
        }
        out_write(fd, out.data, out.len);
    }
    free(blk);
    buf_free(&out);
    return ok ? 0 : -1;
}

#ifdef HAVE_LZMA
static int do_xz(sreader *in, int fd, int alone)
{
    lzma_stream s = LZMA_STREAM_INIT;
    if ((alone ? lzma_alone_decoder(&s, UINT64_MAX) : lzma_stream_decoder(&s, UINT64_MAX, LZMA_CONCATENATED)) != LZMA_OK)
        return -1;
    unsigned char *ib = xmalloc(CHUNK), *ob = xmalloc(CHUNK);
    lzma_ret r = LZMA_OK;
    lzma_action act = LZMA_RUN;
    while (r == LZMA_OK) {
        if (!s.avail_in && act == LZMA_RUN) {
            long n = sreader_read(in, ib, CHUNK);
            if (n < 0)
                break;
            if (n == 0)
                act = LZMA_FINISH;
            s.next_in = ib;
            s.avail_in = (size_t)n;
        }
        s.next_out = ob;
        s.avail_out = CHUNK;
        r = lzma_code(&s, act);
        out_write(fd, ob, CHUNK - s.avail_out);
    }
    lzma_end(&s);
    free(ib);
    free(ob);
    return r == LZMA_STREAM_END ? 0 : -1;
}
#endif

#ifdef HAVE_BZ2
static int do_bz2(sreader *in, int fd)
{
    bz_stream s;
    memset(&s, 0, sizeof s);
    if (BZ2_bzDecompressInit(&s, 0, 0) != BZ_OK)
        return -1;
    char *ib = xmalloc(CHUNK), *ob = xmalloc(CHUNK);
    int r = BZ_OK;
    while (r == BZ_OK) {
        if (!s.avail_in) {
            long n = sreader_read(in, ib, CHUNK);
            if (n <= 0)
                break;
            s.next_in = ib;
            s.avail_in = (unsigned)n;
        }
        s.next_out = ob;
        s.avail_out = CHUNK;
        r = BZ2_bzDecompress(&s);
        out_write(fd, ob, CHUNK - s.avail_out);
    }
    BZ2_bzDecompressEnd(&s);
    free(ib);
    free(ob);
    return r == BZ_STREAM_END ? 0 : -1;
}
#endif

#ifdef HAVE_ZSTD
static int do_zstd(sreader *in, int fd)
{
    ZSTD_DStream *ds = ZSTD_createDStream();
    ZSTD_initDStream(ds);
    unsigned char *ib = xmalloc(CHUNK), *ob = xmalloc(CHUNK);
    int ok = 1;
    size_t last = 1;
    for (;;) {
        long n = sreader_read(in, ib, CHUNK);
        if (n < 0) {
            ok = 0;
            break;
        }
        if (n == 0)
            break;
        ZSTD_inBuffer ibuf = {ib, (size_t)n, 0};
        while (ibuf.pos < ibuf.size) {
            ZSTD_outBuffer obuf = {ob, CHUNK, 0};
            last = ZSTD_decompressStream(ds, &obuf, &ibuf);
            if (ZSTD_isError(last)) {
                ok = 0;
                break;
            }
            out_write(fd, ob, obuf.pos);
        }
        if (!ok)
            break;
    }
    for (int guard = 0; ok && last && guard < 1 << 20; guard++) {
        ZSTD_inBuffer ibuf = {ib, 0, 0};
        ZSTD_outBuffer obuf = {ob, CHUNK, 0};
        last = ZSTD_decompressStream(ds, &obuf, &ibuf);
        if (ZSTD_isError(last) || !obuf.pos)
            break;
        out_write(fd, ob, obuf.pos);
    }
    ZSTD_freeDStream(ds);
    free(ib);
    free(ob);
    return ok && last == 0 ? 0 : -1;
}
#endif

rsrc *stream_decompress_to_temp(sreader *in, const char *label, char *err, size_t errlen)
{
    unsigned char h[16];
    int n = sreader_peek(in, h, sizeof h);
    if (n < 0) {
        snprintf(err, errlen, "read error");
        return NULL;
    }
    codec_t c = codec_detect(h, (size_t)n);
    int fd = temp_fd();
    int r;
    switch (c) {
    case CODEC_GZIP: r = do_gzip(in, fd); break;
    case CODEC_LZ4_FRAME: r = do_lz4_frame(in, fd); break;
    case CODEC_LZ4_LEGACY: r = do_lz4_legacy(in, fd); break;
#ifdef HAVE_LZMA
    case CODEC_XZ: r = do_xz(in, fd, 0); break;
    case CODEC_LZMA: r = do_xz(in, fd, 1); break;
#endif
#ifdef HAVE_BZ2
    case CODEC_BZIP2: r = do_bz2(in, fd); break;
#endif
#ifdef HAVE_ZSTD
    case CODEC_ZSTD: r = do_zstd(in, fd); break;
#endif
#if !defined(HAVE_LZMA) || !defined(HAVE_BZ2) || !defined(HAVE_ZSTD)
#ifndef HAVE_LZMA
    case CODEC_XZ:
    case CODEC_LZMA:
#endif
#ifndef HAVE_BZ2
    case CODEC_BZIP2:
#endif
#ifndef HAVE_ZSTD
    case CODEC_ZSTD:
#endif
        close(fd);
        snprintf(err, errlen, "%s: %s data needs a decompressor this build lacks", label, codec_name(c));
        return NULL;
#endif
    default: r = do_raw(in, fd); break;
    }
    if (r < 0) {
        close(fd);
        snprintf(err, errlen, "%s: corrupt or truncated %s data", label, codec_name(c));
        return NULL;
    }
    return rsrc_open_fd(fd, label);
}
